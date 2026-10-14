/**
 * Swift symbol names (`$s…`, Swift 5 and later; `$S…`, Swift 4.2) back to
 * what they declare, printed as Apple's `swift-demangle` prints them: in full
 * (`HelloKit.Counter.increment(by: Swift.Int) -> Swift.Int`) and simplified,
 * as its `--simplified` does (`Counter.increment(by:)`), for the listing.
 *
 * The mangling is a postfix language: each operator pops what it applies to
 * from a stack of nodes and pushes the node it makes, so a symbol becomes a
 * tree, which is then printed. Names already seen are referred to again by
 * substitutions (`A…`), and words already seen inside identifiers by letters.
 * The grammar is the one in the Swift repository's docs/ABI/Mangling.rst; the
 * tree has the shape and the node names of the Swift runtime's own demangler,
 * so that `tools/verify-swift.mjs` can compare the two node by node, and the
 * printer follows the text `swift-demangle` gives for each node.
 *
 * A name that does not parse, or holds a node the printer does not know, is
 * not demangled at all rather than printed wrong.
 */

export class SwiftNode {
  children: SwiftNode[] = [];
  constructor(
    readonly kind: string,
    readonly text?: string,
    readonly index?: number,
  ) {}
  get first(): SwiftNode {
    return this.children[0]!;
  }
  child(i: number): SwiftNode {
    const c = this.children[i];
    if (!c) throw new Bad();
    return c;
  }
  get count(): number {
    return this.children.length;
  }
}

/** A malformed symbol, or a node the printer does not know. */
class Bad extends Error {}

type N = SwiftNode | null;

const isDigit = (c: string) => c >= '0' && c <= '9';
const isLower = (c: string) => c >= 'a' && c <= 'z';
const isUpper = (c: string) => c >= 'A' && c <= 'Z';
const isLetter = (c: string) => isLower(c) || isUpper(c);

/** The standard types `S<letter>` names (and `Sc<letter>`, the concurrency ones). */
const STANDARD: Record<string, [string, string]> = {
  A: ['Structure', 'AutoreleasingUnsafeMutablePointer'], a: ['Structure', 'Array'], b: ['Structure', 'Bool'],
  D: ['Structure', 'Dictionary'], d: ['Structure', 'Double'], f: ['Structure', 'Float'], h: ['Structure', 'Set'],
  I: ['Structure', 'DefaultIndices'], i: ['Structure', 'Int'], J: ['Structure', 'Character'], N: ['Structure', 'ClosedRange'],
  n: ['Structure', 'Range'], O: ['Structure', 'ObjectIdentifier'], P: ['Structure', 'UnsafePointer'],
  p: ['Structure', 'UnsafeMutablePointer'], R: ['Structure', 'UnsafeBufferPointer'], r: ['Structure', 'UnsafeMutableBufferPointer'],
  S: ['Structure', 'String'], s: ['Structure', 'Substring'], u: ['Structure', 'UInt'], V: ['Structure', 'UnsafeRawPointer'],
  v: ['Structure', 'UnsafeMutableRawPointer'], W: ['Structure', 'UnsafeRawBufferPointer'], w: ['Structure', 'UnsafeMutableRawBufferPointer'],
  q: ['Enum', 'Optional'],
  B: ['Protocol', 'BinaryFloatingPoint'], E: ['Protocol', 'Encodable'], e: ['Protocol', 'Decodable'], F: ['Protocol', 'FloatingPoint'],
  G: ['Protocol', 'RandomNumberGenerator'], H: ['Protocol', 'Hashable'], j: ['Protocol', 'Numeric'], K: ['Protocol', 'BidirectionalCollection'],
  k: ['Protocol', 'RandomAccessCollection'], L: ['Protocol', 'Comparable'], l: ['Protocol', 'Collection'], M: ['Protocol', 'MutableCollection'],
  m: ['Protocol', 'RangeReplaceableCollection'], Q: ['Protocol', 'Equatable'], T: ['Protocol', 'Sequence'], t: ['Protocol', 'IteratorProtocol'],
  U: ['Protocol', 'UnsignedInteger'], X: ['Protocol', 'RangeExpression'], x: ['Protocol', 'Strideable'], Y: ['Protocol', 'RawRepresentable'],
  y: ['Protocol', 'StringProtocol'], Z: ['Protocol', 'SignedInteger'], z: ['Protocol', 'BinaryInteger'],
};
const CONCURRENCY: Record<string, [string, string]> = {
  A: ['Protocol', 'Actor'], C: ['Structure', 'CheckedContinuation'], c: ['Structure', 'UnsafeContinuation'],
  E: ['Structure', 'CancellationError'], e: ['Structure', 'UnownedSerialExecutor'], F: ['Protocol', 'Executor'],
  f: ['Protocol', 'SerialExecutor'], G: ['Structure', 'TaskGroup'], g: ['Structure', 'ThrowingTaskGroup'],
  h: ['Protocol', 'TaskExecutor'], I: ['Protocol', 'AsyncIteratorProtocol'], i: ['Protocol', 'AsyncSequence'],
  J: ['Structure', 'UnownedJob'], M: ['Class', 'MainActor'], P: ['Structure', 'TaskPriority'], S: ['Structure', 'AsyncStream'],
  s: ['Structure', 'AsyncThrowingStream'], T: ['Structure', 'Task'], t: ['Structure', 'UnsafeCurrentTask'],
};

/** Value witnesses (`w<two letters>`), as the printer names them. */
const VALUE_WITNESSES: Record<string, string> = {
  al: 'allocateBuffer', ca: 'assignWithCopy', ta: 'assignWithTake', de: 'deallocateBuffer', xx: 'destroy', XX: 'destroyBuffer',
  Xx: 'destroyArray', CP: 'initializeBufferWithCopyOfBuffer', Cp: 'initializeBufferWithCopy', cp: 'initializeWithCopy',
  Tk: 'initializeBufferWithTake', tk: 'initializeWithTake', pr: 'projectBuffer', TK: 'initializeBufferWithTakeOfBuffer',
  Cc: 'initializeArrayWithCopy', Tt: 'initializeArrayWithTakeFrontToBack', tT: 'initializeArrayWithTakeBackToFront',
  xs: 'storeExtraInhabitant', xg: 'getExtraInhabitantIndex', ug: 'getEnumTag', up: 'destructiveProjectEnumData',
  ui: 'destructiveInjectEnumTag', et: 'getEnumTagSinglePayload', st: 'storeEnumTagSinglePayload',
};

const CONTEXTS = new Set([
  'Allocator', 'AnonymousContext', 'Class', 'Constructor', 'Deallocator', 'IsolatedDeallocator', 'DefaultArgumentInitializer',
  'Destructor', 'DidSet', 'Enum', 'ExplicitClosure', 'Extension', 'Function', 'Getter', 'GlobalGetter', 'IVarInitializer',
  'IVarDestroyer', 'ImplicitClosure', 'Initializer', 'InitAccessor', 'MaterializeForSet', 'ModifyAccessor', 'Modify2Accessor',
  'Module', 'NativeOwningAddressor', 'NativeOwningMutableAddressor', 'NativePinningAddressor', 'NativePinningMutableAddressor',
  'OtherNominalType', 'OwningAddressor', 'OwningMutableAddressor', 'PropertyWrapperBackingInitializer',
  'PropertyWrapperInitFromProjectedValue', 'PropertyWrappedFieldInitAccessor', 'Protocol', 'ProtocolSymbolicReference', 'ReadAccessor', 'Read2Accessor', 'Setter',
  'Static', 'Structure', 'Subscript', 'TypeSymbolicReference', 'TypeAlias', 'UnsafeAddressor', 'UnsafeMutableAddressor',
  'Variable', 'WillSet', 'OpaqueReturnTypeOf', 'AutoDiffFunction', 'AccessorAttachedMacroExpansion',
  'MemberAttributeAttachedMacroExpansion', 'MemberAttachedMacroExpansion', 'PeerAttachedMacroExpansion',
  'ConformanceAttachedMacroExpansion', 'ExtensionAttachedMacroExpansion', 'PreambleAttachedMacroExpansion',
  'BodyAttachedMacroExpansion', 'FreestandingMacroExpansion', 'MacroExpansionUniqueName', 'MacroExpansionLoc', 'Macro',
  'GenericTypeParamDecl', 'BuiltinTupleType',
]);
const MACRO_EXPANSIONS = new Set([
  'AccessorAttachedMacroExpansion', 'MemberAttributeAttachedMacroExpansion', 'FreestandingMacroExpansion',
  'MemberAttachedMacroExpansion', 'PeerAttachedMacroExpansion', 'ConformanceAttachedMacroExpansion',
  'ExtensionAttachedMacroExpansion', 'MacroExpansionLoc', 'BodyAttachedMacroExpansion', 'PreambleAttachedMacroExpansion',
]);
const FUNCTION_ATTRS = new Set([
  'FunctionSignatureSpecialization', 'GenericSpecialization', 'GenericSpecializationPrespecialized', 'InlinedGenericFunction',
  'GenericSpecializationNotReAbstracted', 'GenericPartialSpecialization', 'GenericPartialSpecializationNotReAbstracted',
  'GenericSpecializationInResilienceDomain', 'ObjCAttribute', 'NonObjCAttribute', 'DynamicAttribute',
  'DirectMethodReferenceAttribute', 'VTableAttribute', 'PartialApplyForwarder', 'PartialApplyObjCForwarder', 'OutlinedVariable',
  'OutlinedReadOnlyObject', 'OutlinedBridgedMethod', 'MergedFunction', 'DistributedThunk', 'DistributedAccessor',
  'DynamicallyReplaceableFunctionImpl', 'DynamicallyReplaceableFunctionKey', 'DynamicallyReplaceableFunctionVar',
  'AsyncFunctionPointer', 'AsyncAwaitResumePartialFunction', 'AsyncSuspendResumePartialFunction', 'AccessibleFunctionRecord',
  'BackDeploymentThunk', 'BackDeploymentFallback', 'HasSymbolQuery', 'CoroFunctionPointer', 'DefaultOverride',
]);
const DECL_NAMES = new Set([
  'Identifier', 'LocalDeclName', 'PrivateDeclName', 'RelatedEntityDeclName', 'PrefixOperator', 'PostfixOperator',
  'InfixOperator', 'TypeSymbolicReference', 'ProtocolSymbolicReference',
]);
const ANY_GENERIC = new Set([
  'Structure', 'Class', 'Enum', 'Protocol', 'ProtocolSymbolicReference', 'OtherNominalType', 'TypeAlias',
  'TypeSymbolicReference', 'BuiltinTupleType',
]);
const REQUIREMENTS = new Set([
  'DependentGenericParamPackMarker', 'DependentGenericParamValueMarker', 'DependentGenericSameTypeRequirement',
  'DependentGenericSameShapeRequirement', 'DependentGenericLayoutRequirement', 'DependentGenericConformanceRequirement',
  'DependentGenericInverseConformanceRequirement',
]);
const ANY_CONFORMANCES = new Set([
  'ConcreteProtocolConformance', 'PackProtocolConformance', 'DependentProtocolConformanceRoot',
  'DependentProtocolConformanceInherited', 'DependentProtocolConformanceAssociated',
]);
const DEPENDENT_CONFORMANCES = new Set(['DependentProtocolConformanceRoot', 'DependentProtocolConformanceInherited', 'DependentProtocolConformanceAssociated']);

/** Function signature specialization parameter kinds: the low six bits a kind, the bits above it options. */
const FSS = {
  ConstantPropFunction: 0, ConstantPropGlobal: 1, ConstantPropInteger: 2, ConstantPropFloat: 3, ConstantPropString: 4,
  ClosureProp: 5, BoxToValue: 6, BoxToStack: 7, InOutToOut: 8, ConstantPropKeyPath: 9, ClosurePropPreviousArg: 10,
  ClosurePropEscaping: 11,
  Dead: 1 << 6, OwnedToGuaranteed: 1 << 7, SROA: 1 << 8, GuaranteedToOwned: 1 << 9, ExistentialToGeneric: 1 << 10,
};

/** Words of an identifier, for the word substitutions after it. */
const isWordStart = (c: string) => c !== '' && !isDigit(c) && c !== '_';
const isWordEnd = (c: string, prev: string) => c === '_' || c === '' || (!isUpper(prev) && isUpper(c));

class Demangler {
  private pos = 0;
  private stack: SwiftNode[] = [];
  private subs: SwiftNode[] = [];
  private words: string[] = [];
  private steps = 0;

  constructor(private readonly s: string) {}

  private peek(): string {
    return this.s[this.pos] ?? '';
  }
  private next(): string {
    return this.s[this.pos++] ?? '';
  }
  private nextIf(c: string): boolean {
    if (this.s.startsWith(c, this.pos)) {
      this.pos += c.length;
      return true;
    }
    return false;
  }
  private back(): void {
    this.pos--;
  }

  private node(kind: string, text?: string, index?: number): SwiftNode {
    return new SwiftNode(kind, text, index);
  }
  private withChildren(kind: string, ...children: N[]): N {
    if (children.some((c) => !c)) return null;
    const n = this.node(kind);
    n.children.push(...(children as SwiftNode[]));
    return n;
  }
  private type(child: N): N {
    return this.withChildren('Type', child);
  }
  /** Adds a child; with either one missing the result is missing too. */
  private add(parent: N, child: N): N {
    if (!parent || !child) return null;
    parent.children.push(child);
    return parent;
  }
  /** Adds a child if there is one. */
  private addIf(parent: SwiftNode, child: N): void {
    if (child) parent.children.push(child);
  }
  private changeKind(n: N, kind: string): N {
    if (!n) return null;
    const out = this.node(kind, n.text, n.index);
    out.children.push(...n.children);
    return out;
  }
  private swiftType(kind: string, name: string): SwiftNode {
    return this.type(this.withChildren(kind, this.node('Module', 'Swift'), this.node('Identifier', name)))!;
  }

  private push(n: SwiftNode): void {
    this.stack.push(n);
  }
  private pop(test?: string | Set<string> | ((kind: string) => boolean)): N {
    const top = this.stack[this.stack.length - 1];
    if (!top) return null;
    if (test !== undefined) {
      if (typeof test === 'string' ? top.kind !== test : test instanceof Set ? !test.has(top.kind) : !test(top.kind)) return null;
    }
    return this.stack.pop()!;
  }
  private popTypeChild(): N {
    const t = this.pop('Type');
    return t ? t.children[0] ?? null : null;
  }
  private popAnyGeneric(): N {
    const c = this.popTypeChild();
    return c && ANY_GENERIC.has(c.kind) ? c : null;
  }
  private popModule(): N {
    const ident = this.pop('Identifier');
    if (ident) return this.changeKind(ident, 'Module');
    return this.pop('Module');
  }
  private popContext(): N {
    const mod = this.popModule();
    if (mod) return mod;
    const t = this.pop('Type');
    if (t) {
      if (t.count !== 1 || !CONTEXTS.has(t.first.kind)) return null;
      return t.first;
    }
    return this.pop(CONTEXTS);
  }
  private popEntity(): N {
    return this.pop((k) => k === 'Type' || CONTEXTS.has(k));
  }
  private addSub(n: N): void {
    if (n) this.subs.push(n);
  }

  private natural(): number {
    if (!isDigit(this.peek())) return -1000;
    let n = 0;
    while (isDigit(this.peek())) {
      n = n * 10 + Number(this.next());
      if (n > 0x7fffffff) return -1000;
    }
    return n;
  }
  private index(): number {
    if (this.nextIf('_')) return 0;
    const n = this.natural();
    if (n >= 0 && this.nextIf('_')) return n + 1;
    return -1000;
  }
  private indexNode(): N {
    const i = this.index();
    return i >= 0 ? this.node('Number', undefined, i) : null;
  }

  demangleSymbol(): N {
    if (this.s.startsWith('_$s') || this.s.startsWith('_$S') || this.s.startsWith('_$e')) this.pos = 3;
    else if (this.s.startsWith('$s') || this.s.startsWith('$S') || this.s.startsWith('$e')) this.pos = 2;
    else return null;
    while (this.pos < this.s.length) {
      if (++this.steps > 20000) return null;
      const n = this.operator();
      if (!n) return null;
      this.push(n);
    }
    const top = this.node('Global');
    const suffix = this.pop('Suffix');
    let parent = top;
    for (let attr = this.pop(FUNCTION_ATTRS); attr; attr = this.pop(FUNCTION_ATTRS)) {
      parent.children.push(attr);
      if (attr.kind === 'PartialApplyForwarder' || attr.kind === 'PartialApplyObjCForwarder') parent = attr;
    }
    for (const n of this.stack) parent.children.push(n.kind === 'Type' ? n.first : n);
    if (suffix) top.children.push(suffix);
    return top.count ? top : null;
  }

  private operator(): N {
    const c = this.next();
    switch (c) {
      case 'A': return this.multiSubstitutions();
      case 'B': return this.builtinType();
      case 'C': return this.anyGenericType('Class');
      case 'D': return this.withChildren('TypeMangling', this.pop('Type'));
      case 'E': return this.extensionContext();
      case 'F': return this.plainFunction();
      case 'G': return this.boundGenericType();
      case 'H': {
        switch (this.next()) {
          case 'A': return this.dependentConformanceAssociated();
          case 'C': return this.concreteConformance();
          case 'D': return this.dependentConformanceRoot();
          case 'I': return this.dependentConformanceInherited();
          case 'P': return this.withChildren('ProtocolConformanceRefInTypeModule', this.popProtocol());
          case 'p': return this.withChildren('ProtocolConformanceRefInProtocolModule', this.popProtocol());
          case 'X': return this.withChildren('PackProtocolConformance', this.popAnyConformanceList());
          case 'c': return this.withChildren('ProtocolConformanceDescriptorRecord', this.popConformance());
          case 'n': return this.withChildren('NominalTypeDescriptorRecord', this.pop('Type'));
          case 'o': return this.withChildren('OpaqueTypeDescriptorRecord', this.pop());
          case 'r': return this.withChildren('ProtocolDescriptorRecord', this.popProtocol());
          case 'F': return this.node('AccessibleFunctionRecord');
          default:
            this.back();
            this.back();
            return this.identifier();
        }
      }
      case 'I': return this.implFunctionType();
      case 'K': return this.node('ThrowsAnnotation');
      case 'L': return this.localIdentifier();
      case 'M': return this.metatype();
      case 'N': return this.withChildren('TypeMetadata', this.pop('Type'));
      case 'O': return this.anyGenericType('Enum');
      case 'P': return this.anyGenericType('Protocol');
      case 'Q': return this.archetype();
      case 'R': return this.genericRequirement();
      case 'S': return this.standardSubstitution();
      case 'T': return this.thunkOrSpecialization();
      case 'V': return this.anyGenericType('Structure');
      case 'W': return this.witness();
      case 'X': return this.specialType();
      case 'Y': return this.typeAnnotation();
      case 'Z': return this.withChildren('Static', this.popEntity());
      case 'a': return this.anyGenericType('TypeAlias');
      case 'c': return this.popFunctionType('FunctionType');
      case 'd': return this.node('VariadicMarker');
      case 'f': return this.functionEntity();
      case 'g': return this.retroactiveConformance();
      case 'h': return this.type(this.withChildren('Shared', this.popTypeChild()));
      case 'i': return this.subscript();
      case 'l': return this.genericSignature(false);
      case 'm': return this.type(this.withChildren('Metatype', this.pop('Type')));
      case 'n': return this.type(this.withChildren('Owned', this.popTypeChild()));
      case 'o': return this.operatorIdentifier();
      case 'p': return this.type(this.protocolList());
      case 'q': return this.type(this.genericParamIndex());
      case 'r': return this.genericSignature(true);
      case 's': return this.node('Module', 'Swift');
      case 't': return this.popTuple();
      case 'u': return this.genericType();
      case 'v': return this.variable();
      case 'w': return this.valueWitness();
      case 'x': return this.type(this.genericParam(0, 0));
      case 'y': return this.node('EmptyList');
      case 'z': return this.type(this.withChildren('InOut', this.popTypeChild()));
      case '_': return this.node('FirstElementMarker');
      case '.':
        this.back();
        return this.suffix();
      case '':
        return null;
      default:
        this.back();
        return this.identifier();
    }
  }

  private suffix(): SwiftNode {
    const text = this.s.slice(this.pos);
    this.pos = this.s.length;
    return this.node('Suffix', text);
  }

  private identifier(): N {
    let wordSubsts = false;
    let punycoded = false;
    if (!isDigit(this.peek())) return null;
    if (this.peek() === '0') {
      this.next();
      if (this.peek() === '0') {
        this.next();
        punycoded = true;
      } else wordSubsts = true;
    }
    let ident = '';
    do {
      while (wordSubsts && isLetter(this.peek())) {
        const c = this.next();
        let w: number;
        if (isLower(c)) w = c.charCodeAt(0) - 97;
        else {
          w = c.charCodeAt(0) - 65;
          wordSubsts = false;
        }
        if (w >= this.words.length) return null;
        ident += this.words[w];
      }
      if (this.nextIf('0')) break;
      const length = this.natural();
      if (length <= 0) return null;
      if (punycoded) this.nextIf('_');
      if (this.pos + length > this.s.length) return null;
      const slice = this.s.slice(this.pos, this.pos + length);
      if (punycoded) {
        const decoded = punycode(slice);
        if (decoded === null) return null;
        ident += decoded;
      } else {
        ident += slice;
        let start = -1;
        for (let i = 0; i <= slice.length; i++) {
          const c = i < slice.length ? slice[i]! : '';
          if (start >= 0 && isWordEnd(c, slice[i - 1]!)) {
            if (i - start >= 2 && this.words.length < 26) this.words.push(slice.slice(start, i));
            start = -1;
          }
          if (start < 0 && isWordStart(c)) start = i;
        }
      }
      this.pos += length;
    } while (wordSubsts);
    if (!ident) return null;
    const n = this.node('Identifier', ident);
    this.addSub(n);
    return n;
  }

  private operatorIdentifier(): N {
    const ident = this.pop('Identifier');
    if (!ident) return null;
    const table = '& @/= >    <*!|+?%-~   ^ .';
    let op = '';
    for (const c of ident.text!) {
      if (c.charCodeAt(0) >= 0x80) {
        op += c;
        continue;
      }
      if (!isLower(c)) return null;
      const o = table[c.charCodeAt(0) - 97]!;
      if (o === ' ') return null;
      op += o;
    }
    switch (this.next()) {
      case 'i': return this.node('InfixOperator', op);
      case 'p': return this.node('PrefixOperator', op);
      case 'P': return this.node('PostfixOperator', op);
      default: return null;
    }
  }

  private localIdentifier(): N {
    if (this.nextIf('L')) {
      const discriminator = this.pop('Identifier');
      const name = this.pop(DECL_NAMES);
      return this.withChildren('PrivateDeclName', discriminator, name);
    }
    if (this.nextIf('l')) return this.withChildren('PrivateDeclName', this.pop('Identifier'));
    const c = this.peek();
    if ((c >= 'a' && c <= 'j') || (c >= 'A' && c <= 'J')) {
      this.next();
      const result = this.node('RelatedEntityDeclName');
      result.children.push(this.node('Identifier', c));
      return this.add(result, this.pop());
    }
    const discriminator = this.indexNode();
    const name = this.pop(DECL_NAMES);
    return this.withChildren('LocalDeclName', discriminator, name);
  }

  private multiSubstitutions(): N {
    let repeat = -1;
    for (;;) {
      const c = this.next();
      if (c === '') return null;
      if (isLower(c)) {
        const n = this.pushMulti(repeat, c.charCodeAt(0) - 97);
        if (!n) return null;
        this.push(n);
        repeat = -1;
        continue;
      }
      if (isUpper(c)) return this.pushMulti(repeat, c.charCodeAt(0) - 65);
      if (c === '_') {
        const i = repeat + 27;
        return this.subs[i] ?? null;
      }
      this.back();
      repeat = this.natural();
      if (repeat < 0) return null;
    }
  }
  private pushMulti(repeat: number, i: number): N {
    const n = this.subs[i];
    if (!n || repeat > 2048) return null;
    while (repeat-- > 1) this.push(n);
    return n;
  }

  private standardSubstitution(): N {
    const c = this.next();
    if (c === 'o') return this.node('Module', '__C');
    if (c === 'C') return this.node('Module', '__C_Synthesized');
    if (c === 'g') {
      const optional = this.type(this.withChildren('BoundGenericEnum', this.swiftType('Enum', 'Optional'), this.withChildren('TypeList', this.pop('Type'))));
      this.addSub(optional);
      return optional;
    }
    this.back();
    const repeat = this.natural();
    if (repeat > 2048) return null;
    const second = this.nextIf('c');
    const entry = (second ? CONCURRENCY : STANDARD)[this.next()];
    if (!entry) return null;
    const n = this.swiftType(entry[0], entry[1]);
    for (let r = repeat; r > 1; r--) this.push(n);
    return n;
  }

  private builtinType(): N {
    let t: N;
    const c = this.next();
    switch (c) {
      case 'b': t = this.node('BuiltinTypeName', 'Builtin.BridgeObject'); break;
      case 'B': t = this.node('BuiltinTypeName', 'Builtin.UnsafeValueBuffer'); break;
      case 'e': t = this.node('BuiltinTypeName', 'Builtin.Executor'); break;
      case 'f':
      case 'i': {
        const size = this.index() - 1;
        if (size <= 0 || size > 4096) return null;
        t = this.node('BuiltinTypeName', `${c === 'f' ? 'Builtin.FPIEEE' : 'Builtin.Int'}${size}`);
        break;
      }
      case 'I': t = this.node('BuiltinTypeName', 'Builtin.IntLiteral'); break;
      case 'v': {
        const elements = this.index() - 1;
        if (elements <= 0 || elements > 4096) return null;
        const element = this.popTypeChild();
        if (!element || element.kind !== 'BuiltinTypeName' || !element.text!.startsWith('Builtin.')) return null;
        t = this.node('BuiltinTypeName', `Builtin.Vec${elements}x${element.text!.slice(8)}`);
        break;
      }
      case 'O': t = this.node('BuiltinTypeName', 'Builtin.UnknownObject'); break;
      case 'o': t = this.node('BuiltinTypeName', 'Builtin.NativeObject'); break;
      case 'p': t = this.node('BuiltinTypeName', 'Builtin.RawPointer'); break;
      case 'j': t = this.node('BuiltinTypeName', 'Builtin.Job'); break;
      case 'D': t = this.node('BuiltinTypeName', 'Builtin.DefaultActorStorage'); break;
      case 'd': t = this.node('BuiltinTypeName', 'Builtin.NonDefaultDistributedActorStorage'); break;
      case 'c': t = this.node('BuiltinTypeName', 'Builtin.RawUnsafeContinuation'); break;
      case 't': t = this.node('BuiltinTypeName', 'Builtin.SILToken'); break;
      case 'w': t = this.node('BuiltinTypeName', 'Builtin.Word'); break;
      case 'P': t = this.node('BuiltinTypeName', 'Builtin.PackIndex'); break;
      case 'T': t = this.node('BuiltinTupleType'); break;
      default: return null;
    }
    return this.type(t);
  }

  private anyGenericType(kind: string): N {
    const name = this.pop(DECL_NAMES);
    const ctx = this.popContext();
    const t = this.type(this.withChildren(kind, ctx, name));
    this.addSub(t);
    return t;
  }

  private extensionContext(): N {
    const sig = this.pop('DependentGenericSignature');
    const mod = this.popModule();
    const t = this.popAnyGeneric();
    let ext = this.withChildren('Extension', mod, t);
    if (sig) ext = this.add(ext, sig);
    return ext;
  }

  private plainFunction(): N {
    const sig = this.pop('DependentGenericSignature');
    let t = this.popFunctionType('FunctionType');
    const labels = this.popFunctionParamLabels(t);
    if (sig) t = this.type(this.withChildren('DependentGenericType', sig, t));
    const name = this.pop(DECL_NAMES);
    const ctx = this.popContext();
    return labels ? this.withChildren('Function', ctx, name, labels, t) : this.withChildren('Function', ctx, name, t);
  }

  private popFunctionType(kind: string, clangType = false): N {
    const fn: N = this.node(kind);
    if (clangType) {
      const ct = this.clangType();
      if (!ct) return null;
      fn.children.push(ct);
    }
    this.addIf(fn, this.pop('GlobalActorFunctionType'));
    this.addIf(fn, this.pop('IsolatedAnyFunctionType'));
    this.addIf(fn, this.pop('NonIsolatedCallerFunctionType'));
    this.addIf(fn, this.pop('SendingResultFunctionType'));
    this.addIf(fn, this.pop((k) => k === 'ThrowsAnnotation' || k === 'TypedThrowsAnnotation'));
    this.addIf(fn, this.pop('ConcurrentFunctionType'));
    this.addIf(fn, this.pop('DifferentiableFunctionType'));
    this.addIf(fn, this.pop('AsyncAnnotation'));
    let out = this.add(fn, this.popFunctionParams('ArgumentTuple'));
    out = this.add(out, this.popFunctionParams('ReturnType'));
    return this.type(out);
  }

  private clangType(): N {
    const length = this.natural();
    if (length < 0 || this.pos + length > this.s.length) return null;
    const text = this.s.slice(this.pos, this.pos + length);
    this.pos += length;
    return this.node('ClangType', text);
  }

  private popFunctionParams(kind: string): N {
    let params: N;
    if (this.pop('EmptyList')) params = this.type(this.node('Tuple'));
    else params = this.pop('Type');
    if (!params) return null;
    const n = kind === 'ArgumentTuple' ? this.node(kind, undefined, params.first.kind === 'Tuple' ? params.first.count : 1) : this.node(kind);
    n.children.push(params);
    return n;
  }

  private popFunctionParamLabels(t: N): N {
    if (this.pop('EmptyList')) return this.node('LabelList');
    if (!t || t.kind !== 'Type') return null;
    let fn = t.first;
    if (fn.kind === 'DependentGenericType') fn = fn.child(1).first;
    if (fn.kind !== 'FunctionType' && fn.kind !== 'NoEscapeFunctionType') return null;
    const args = fn.children.find((c) => c.kind === 'ArgumentTuple');
    if (!args) return null;
    const params = args.first.first;
    const count = params.kind === 'Tuple' ? params.count : 1;
    if (count === 0) return null;
    const labels = this.node('LabelList');
    let any = false;
    for (let i = 0; i < count; i++) {
      const label = this.pop();
      if (!label || (label.kind !== 'Identifier' && label.kind !== 'FirstElementMarker')) return null;
      labels.children.push(label);
      any ||= label.kind !== 'FirstElementMarker';
    }
    if (!any) return this.node('LabelList');
    labels.children.reverse();
    return labels;
  }

  private popTuple(): N {
    const root = this.node('Tuple');
    if (!this.pop('EmptyList')) {
      let first = false;
      do {
        first = !!this.pop('FirstElementMarker');
        const element = this.node('TupleElement');
        this.addIf(element, this.pop('VariadicMarker'));
        const ident = this.pop('Identifier');
        if (ident) element.children.push(this.node('TupleElementName', ident.text));
        const t = this.pop('Type');
        if (!t) return null;
        element.children.push(t);
        root.children.push(element);
      } while (!first);
      root.children.reverse();
    }
    return this.type(root);
  }

  private popTypeList(): N {
    const root = this.node('TypeList');
    if (!this.pop('EmptyList')) {
      let first = false;
      do {
        first = !!this.pop('FirstElementMarker');
        const t = this.pop('Type');
        if (!t) return null;
        root.children.push(t);
      } while (!first);
      root.children.reverse();
    }
    return root;
  }

  private popProtocol(): N {
    const t = this.pop('Type');
    if (t) {
      if (t.count < 1 || !isProtocolNode(t)) return null;
      return t;
    }
    const ref = this.pop('ProtocolSymbolicReference') ?? this.pop('ObjectiveCProtocolSymbolicReference');
    if (ref) return ref;
    const name = this.pop(DECL_NAMES);
    const ctx = this.popContext();
    return this.type(this.withChildren('Protocol', ctx, name));
  }

  private protocolList(): N {
    const list = this.node('TypeList');
    const protocols = this.withChildren('ProtocolList', list)!;
    if (!this.pop('EmptyList')) {
      let first = false;
      do {
        first = !!this.pop('FirstElementMarker');
        const p = this.popProtocol();
        if (!p) return null;
        list.children.push(p);
      } while (!first);
      list.children.reverse();
    }
    return protocols;
  }

  private boundGenerics(lists: SwiftNode[]): { ok: boolean; retro: N } {
    const retro = this.popRetroactiveConformances();
    for (;;) {
      const list = this.node('TypeList');
      lists.push(list);
      for (let t = this.pop('Type'); t; t = this.pop('Type')) list.children.push(t);
      list.children.reverse();
      if (this.pop('EmptyList')) break;
      if (!this.pop('FirstElementMarker')) return { ok: false, retro };
    }
    return { ok: true, retro };
  }

  private popRetroactiveConformances(): N {
    let list: N = null;
    for (let c = this.pop('RetroactiveConformance'); c; c = this.pop('RetroactiveConformance')) {
      list ??= this.node('TypeList');
      list.children.push(c);
    }
    list?.children.reverse();
    return list;
  }

  private boundGenericType(): N {
    const lists: SwiftNode[] = [];
    const { ok, retro } = this.boundGenerics(lists);
    if (!ok) return null;
    const nominal = this.popAnyGeneric();
    const bound = this.boundGenericArgs(nominal, lists, 0);
    if (!bound) return null;
    if (retro) bound.children.push(retro);
    const t = this.type(bound);
    this.addSub(t);
    return t;
  }

  private boundGenericArgs(nominal: N, lists: SwiftNode[], at: number): N {
    if (!nominal || at >= lists.length) return null;
    if (nominal.kind === 'TypeSymbolicReference' || nominal.kind === 'ProtocolSymbolicReference') {
      const remaining = this.node('TypeList');
      for (let i = lists.length - 1; i >= at; i--) remaining.children.push(...lists[i]!.children);
      return this.withChildren('BoundGenericOtherNominalType', this.type(nominal), remaining);
    }
    if (!nominal.count) return null;
    const ctx = nominal.first;
    const consumes = !['Variable', 'Subscript', 'ImplicitClosure', 'ExplicitClosure', 'DefaultArgumentInitializer', 'Initializer',
      'PropertyWrapperBackingInitializer', 'PropertyWrapperInitFromProjectedValue', 'PropertyWrappedFieldInitAccessor', 'Static'].includes(nominal.kind);
    const args = lists[at]!;
    if (consumes) at++;
    if (at < lists.length) {
      let parent: N;
      if (ctx.kind === 'Extension') {
        parent = this.boundGenericArgs(ctx.children[1] ?? null, lists, at);
        parent = this.withChildren('Extension', ctx.first, parent);
        if (parent && ctx.count === 3) parent.children.push(ctx.child(2));
      } else parent = this.boundGenericArgs(ctx, lists, at);
      const rebuilt = this.withChildren(nominal.kind, parent);
      if (!rebuilt) return null;
      rebuilt.children.push(...nominal.children.slice(1));
      nominal = rebuilt;
    }
    if (!consumes || args.count === 0) return nominal;
    const kinds: Record<string, string> = {
      Class: 'BoundGenericClass', Structure: 'BoundGenericStructure', Enum: 'BoundGenericEnum', Protocol: 'BoundGenericProtocol',
      OtherNominalType: 'BoundGenericOtherNominalType', TypeAlias: 'BoundGenericTypeAlias',
    };
    if (nominal.kind === 'Function' || nominal.kind === 'Constructor') return this.withChildren('BoundGenericFunction', nominal, args);
    const kind = kinds[nominal.kind];
    if (!kind) return null;
    return this.withChildren(kind, this.type(nominal), args);
  }

  private genericSignature(counts: boolean): N {
    const sig = this.node('DependentGenericSignature');
    if (counts) {
      while (!this.nextIf('l')) {
        let count = 0;
        if (!this.nextIf('z')) count = this.index() + 1;
        if (count < 0 || this.pos > this.s.length) return null;
        sig.children.push(this.node('DependentGenericParamCount', undefined, count));
      }
    } else sig.children.push(this.node('DependentGenericParamCount', undefined, 1));
    const reqs: SwiftNode[] = [];
    for (let r = this.pop(REQUIREMENTS); r; r = this.pop(REQUIREMENTS)) reqs.push(r);
    sig.children.push(...reqs.reverse());
    return sig;
  }

  private genericParam(depth: number, index: number): N {
    if (depth < 0 || index < 0) return null;
    const n = this.node('DependentGenericParamType');
    n.children.push(this.node('Index', undefined, depth), this.node('Index', undefined, index));
    return n;
  }

  private genericParamIndex(): N {
    if (this.nextIf('d')) {
      const depth = this.index() + 1;
      const index = this.index();
      return this.genericParam(depth, index);
    }
    if (this.nextIf('z')) return this.genericParam(0, 0);
    if (this.nextIf('s')) return this.node('ConstrainedExistentialSelf');
    return this.genericParam(0, this.index() + 1);
  }

  private genericRequirement(): N {
    type TypeKind = 'generic' | 'assoc' | 'compound' | 'substitution';
    type Constraint = 'protocol' | 'baseClass' | 'sameType' | 'sameShape' | 'layout' | 'packMarker' | 'inverse' | 'valueMarker';
    const table: Record<string, [Constraint, TypeKind]> = {
      v: ['packMarker', 'generic'], V: ['valueMarker', 'generic'], c: ['baseClass', 'assoc'], C: ['baseClass', 'compound'],
      b: ['baseClass', 'generic'], B: ['baseClass', 'substitution'], t: ['sameType', 'assoc'], T: ['sameType', 'compound'],
      s: ['sameType', 'generic'], S: ['sameType', 'substitution'], m: ['layout', 'assoc'], M: ['layout', 'compound'],
      l: ['layout', 'generic'], L: ['layout', 'substitution'], p: ['protocol', 'assoc'], P: ['protocol', 'compound'],
      Q: ['protocol', 'substitution'], h: ['sameShape', 'generic'], i: ['inverse', 'generic'], I: ['inverse', 'substitution'],
    };
    let entry = table[this.next()];
    if (!entry) {
      this.back();
      entry = ['protocol', 'generic'];
    }
    const [constraint, typeKind] = entry;
    // An inverse requirement (~Copyable) names the protocol before the type.
    const inverse = constraint === 'inverse' ? this.index() : 0;
    let t: N;
    switch (typeKind) {
      case 'generic': t = this.type(this.genericParamIndex()); break;
      case 'assoc': t = this.associatedTypeSimple(this.genericParamIndex()); this.addSub(t); break;
      case 'compound': t = this.associatedTypeCompound(this.genericParamIndex()); this.addSub(t); break;
      case 'substitution': t = this.pop('Type'); break;
    }
    switch (constraint) {
      case 'valueMarker': return this.withChildren('DependentGenericParamValueMarker', t, this.pop('Type'));
      case 'packMarker': return this.withChildren('DependentGenericParamPackMarker', t);
      case 'protocol': return this.withChildren('DependentGenericConformanceRequirement', t, this.popProtocol());
      case 'inverse':
        if (inverse < 0) return null;
        return this.withChildren('DependentGenericInverseConformanceRequirement', t, this.node('Index', undefined, inverse));
      case 'baseClass': return this.withChildren('DependentGenericConformanceRequirement', t, this.pop('Type'));
      case 'sameType': return this.withChildren('DependentGenericSameTypeRequirement', t, this.pop('Type'));
      case 'sameShape': return this.withChildren('DependentGenericSameShapeRequirement', t, this.pop('Type'));
      case 'layout': {
        const c = this.next();
        let size: N = null;
        let alignment: N = null;
        if (c === 'E' || c === 'M') {
          size = this.indexNode();
          if (!size) return null;
          alignment = this.indexNode();
        } else if (c === 'e' || c === 'm' || c === 'S') {
          size = this.indexNode();
          if (!size) return null;
        } else if (c === '' || !'URNCDTB'.includes(c)) return null;
        const req = this.withChildren('DependentGenericLayoutRequirement', t, this.node('Identifier', c));
        if (req && size) req.children.push(size);
        if (req && alignment) req.children.push(alignment);
        return req;
      }
    }
  }

  private associatedTypeSimple(base: N): N {
    const name = this.popAssocTypeName();
    const baseType = base ? this.type(base) : this.pop('Type');
    return this.type(this.withChildren('DependentMemberType', baseType, name));
  }

  private associatedTypeCompound(base: N): N {
    const names: SwiftNode[] = [];
    let first = false;
    do {
      first = !!this.pop('FirstElementMarker');
      const name = this.popAssocTypeName();
      if (!name) return null;
      names.push(name);
    } while (!first);
    let baseType = base ? this.type(base) : this.pop('Type');
    for (let name = names.pop(); name; name = names.pop()) {
      baseType = this.type(this.withChildren('DependentMemberType', baseType, name));
    }
    return baseType;
  }

  private popAssocTypeName(): N {
    let proto = this.pop('Type');
    if (proto && !isProtocolNode(proto)) return null;
    proto ??= this.pop('ProtocolSymbolicReference') ?? this.pop('ObjectiveCProtocolSymbolicReference');
    const id = this.pop('Identifier');
    const ref = this.withChildren('DependentAssociatedTypeRef', id);
    if (ref && proto) ref.children.push(proto);
    return ref;
  }

  private popAssocTypePath(): N {
    const path = this.node('AssocTypePath');
    let first = false;
    do {
      first = !!this.pop('FirstElementMarker');
      const t = this.popAssocTypeName();
      if (!t) return null;
      path.children.push(t);
    } while (!first);
    path.children.reverse();
    return path;
  }

  private genericType(): N {
    const sig = this.pop('DependentGenericSignature');
    const t = this.pop('Type');
    return this.type(this.withChildren('DependentGenericType', sig, t));
  }

  private archetype(): N {
    switch (this.next()) {
      case 'a': {
        const ident = this.pop('Identifier');
        const base = this.popTypeChild();
        const t = this.type(this.withChildren('AssociatedTypeRef', base, ident));
        this.addSub(t);
        return t;
      }
      case 'O': return this.withChildren('OpaqueReturnTypeOf', this.popContext());
      case 'o': {
        const index = this.index();
        const lists: SwiftNode[] = [];
        const { ok, retro } = this.boundGenerics(lists);
        if (!ok) return null;
        const name = this.pop();
        if (!name || index < 0) return null;
        const opaque = this.withChildren('OpaqueType', name, this.node('Index', undefined, index))!;
        const bound = this.node('TypeList');
        for (let i = lists.length; i-- > 0;) bound.children.push(lists[i]!);
        opaque.children.push(bound);
        if (retro) opaque.children.push(retro);
        const t = this.type(opaque);
        this.addSub(t);
        return t;
      }
      case 'r': return this.type(this.node('OpaqueReturnType'));
      case 'R': {
        const ordinal = this.index();
        if (ordinal < 0) return null;
        return this.type(this.withChildren('OpaqueReturnType', this.node('OpaqueReturnTypeIndex', undefined, ordinal)));
      }
      case 'x': { const t = this.associatedTypeSimple(null); this.addSub(t); return t; }
      case 'X': { const t = this.associatedTypeCompound(null); this.addSub(t); return t; }
      case 'y': { const t = this.associatedTypeSimple(this.genericParamIndex()); this.addSub(t); return t; }
      case 'Y': { const t = this.associatedTypeCompound(this.genericParamIndex()); this.addSub(t); return t; }
      case 'z': { const t = this.associatedTypeSimple(this.genericParam(0, 0)); this.addSub(t); return t; }
      case 'Z': { const t = this.associatedTypeCompound(this.genericParam(0, 0)); this.addSub(t); return t; }
      case 'p': {
        const count = this.popTypeChild();
        const pattern = this.popTypeChild();
        return this.type(this.withChildren('PackExpansion', pattern, count));
      }
      case 'e': {
        const pack = this.popTypeChild();
        const level = this.index();
        if (level < 0) return null;
        return this.type(this.withChildren('PackElement', pack, this.node('PackElementLevel', undefined, level)));
      }
      case 'P': {
        const list = this.popTypeList();
        if (!list) return null;
        return this.type(this.changeKind(list, 'Pack'));
      }
      default: return null;
    }
  }

  private metatype(): N {
    const popped = (kind: string) => this.withChildren(kind, this.pop('Type'));
    switch (this.next()) {
      case 'a': return popped('TypeMetadataAccessFunction');
      case 'A': return this.withChildren('ReflectionMetadataAssocTypeDescriptor', this.popConformance());
      case 'b': return popped('CanonicalSpecializedGenericTypeMetadataAccessFunction');
      case 'B': return this.withChildren('ReflectionMetadataBuiltinDescriptor', this.pop('Type'));
      case 'c': return this.withChildren('ProtocolConformanceDescriptor', this.popConformance());
      case 'C': {
        const t = this.pop('Type');
        if (!t || !ANY_GENERIC.has(t.first.kind)) return null;
        return this.withChildren('ReflectionMetadataSuperclassDescriptor', t.first);
      }
      case 'D':
      case 'd': return popped('TypeMetadataDemanglingCache');
      case 'f': return popped('FullTypeMetadata');
      case 'F': return this.withChildren('ReflectionMetadataFieldDescriptor', this.pop('Type'));
      case 'g': return this.withChildren('OpaqueTypeDescriptorAccessor', this.pop());
      case 'h': return this.withChildren('OpaqueTypeDescriptorAccessorImpl', this.pop());
      case 'i': return popped('TypeMetadataInstantiationFunction');
      case 'I': return popped('TypeMetadataInstantiationCache');
      case 'j': return this.withChildren('OpaqueTypeDescriptorAccessorKey', this.pop());
      case 'J': return this.withChildren('NoncanonicalSpecializedGenericTypeMetadataCache', this.pop());
      case 'k': return this.withChildren('OpaqueTypeDescriptorAccessorVar', this.pop());
      case 'K': return this.withChildren('MetadataInstantiationCache', this.pop());
      case 'l': return popped('TypeMetadataSingletonInitializationCache');
      case 'L': return popped('TypeMetadataLazyCache');
      case 'm': return popped('Metaclass');
      case 'M': return popped('CanonicalSpecializedGenericMetaclass');
      case 'n': return popped('NominalTypeDescriptor');
      case 'N': return popped('NoncanonicalSpecializedGenericTypeMetadata');
      case 'o': return popped('ClassMetadataBaseOffset');
      case 'p': return this.withChildren('ProtocolDescriptor', this.popProtocol());
      case 'P': return popped('GenericTypeMetadataPattern');
      case 'q': return this.withChildren('Uniquable', this.pop());
      case 'Q': return this.withChildren('OpaqueTypeDescriptor', this.pop());
      case 'r': return popped('TypeMetadataCompletionFunction');
      case 'R': return popped('TypeMetadataMangledNameRef');
      case 's': return popped('ObjCResilientClassStub');
      case 'S': return this.withChildren('ProtocolSelfConformanceDescriptor', this.popProtocol());
      case 't': return popped('FullObjCResilientClassStub');
      case 'u': return popped('MethodLookupFunction');
      case 'U': return popped('ObjCMetadataUpdateFunction');
      case 'V': return this.withChildren('PropertyDescriptor', this.popEntity());
      case 'X': return this.privateContextDescriptor();
      case 'z': return popped('CanonicalPrespecializedGenericTypeCachingOnceToken');
      default: return null;
    }
  }

  private privateContextDescriptor(): N {
    switch (this.next()) {
      case 'E': return this.withChildren('ExtensionDescriptor', this.popContext());
      case 'M': return this.withChildren('ModuleDescriptor', this.popModule());
      case 'Y': {
        const discriminator = this.pop();
        const ctx = this.popContext();
        return this.withChildren('AnonymousDescriptor', ctx, discriminator);
      }
      case 'X': return this.withChildren('AnonymousDescriptor', this.popContext());
      case 'A': {
        const path = this.popAssocTypePath();
        const base = this.pop('Type');
        return this.withChildren('AssociatedTypeGenericParamRef', base, path);
      }
      default: return null;
    }
  }

  private popConformance(): N {
    const sig = this.pop('DependentGenericSignature');
    const mod = this.popModule();
    const proto = this.popProtocol();
    let t = this.pop('Type');
    let ident: N = null;
    if (!t) {
      ident = this.pop('Identifier');
      t = this.pop('Type');
    }
    if (sig) t = this.type(this.withChildren('DependentGenericType', sig, t));
    const conf = this.withChildren('ProtocolConformance', t, proto, mod);
    if (conf && ident) conf.children.push(ident);
    return conf;
  }

  private popAnyConformance(): N {
    return this.pop(ANY_CONFORMANCES);
  }
  private popAnyConformanceList(): N {
    const list = this.node('AnyProtocolConformanceList');
    if (!this.pop('EmptyList')) {
      let first = false;
      do {
        first = !!this.pop('FirstElementMarker');
        const c = this.popAnyConformance();
        if (!c) return null;
        list.children.push(c);
      } while (!first);
      list.children.reverse();
    }
    return list;
  }
  private retroactiveConformance(): N {
    const index = this.index();
    if (index < 0) return null;
    const conf = this.popAnyConformance();
    if (!conf) return null;
    return this.withChildren('RetroactiveConformance', this.node('Index', undefined, index), conf);
  }
  private concreteConformance(): N {
    const conditional = this.popAnyConformanceList();
    const ref = this.pop('ProtocolConformanceRefInTypeModule') ?? this.pop('ProtocolConformanceRefInProtocolModule') ?? this.conformanceRef();
    const t = this.pop('Type');
    return this.withChildren('ConcreteProtocolConformance', t, ref, conditional);
  }
  private conformanceRef(): N {
    const mod = this.popModule();
    const proto = this.popProtocol();
    return this.withChildren('ProtocolConformanceRefInOtherModule', proto, mod);
  }
  private dependentConformanceIndex(): N {
    const index = this.index();
    if (index <= 0) return null;
    if (index === 1) return this.node('UnknownIndex');
    return this.node('Index', undefined, index - 2);
  }
  private dependentConformanceRoot(): N {
    const index = this.dependentConformanceIndex();
    const proto = this.popProtocol();
    const t = this.pop('Type');
    return this.withChildren('DependentProtocolConformanceRoot', t, proto, index);
  }
  private dependentConformanceInherited(): N {
    const index = this.dependentConformanceIndex();
    const proto = this.popProtocol();
    const nested = this.pop(DEPENDENT_CONFORMANCES);
    return this.withChildren('DependentProtocolConformanceInherited', nested, proto, index);
  }
  private dependentConformanceAssociated(): N {
    const index = this.dependentConformanceIndex();
    const proto = this.popProtocol();
    const t = this.pop('Type');
    const assoc = this.withChildren('DependentAssociatedConformance', t, proto);
    const nested = this.pop(DEPENDENT_CONFORMANCES);
    return this.withChildren('DependentProtocolConformanceAssociated', nested, assoc, index);
  }

  private witness(): N {
    const c = this.next();
    switch (c) {
      case 'C': return this.withChildren('EnumCase', this.popEntity());
      case 'V': return this.withChildren('ValueWitnessTable', this.pop('Type'));
      case 'v': {
        const d = this.next();
        if (d !== 'd' && d !== 'i') return null;
        return this.withChildren('FieldOffset', this.node('Directness', undefined, d === 'd' ? 0 : 1), this.popEntity());
      }
      case 'S': return this.withChildren('ProtocolSelfConformanceWitnessTable', this.popProtocol());
      case 'P': return this.withChildren('ProtocolWitnessTable', this.popConformance());
      case 'p': return this.withChildren('ProtocolWitnessTablePattern', this.popConformance());
      case 'G': return this.withChildren('GenericProtocolWitnessTable', this.popConformance());
      case 'I': return this.withChildren('GenericProtocolWitnessTableInstantiationFunction', this.popConformance());
      case 'r': return this.withChildren('ResilientProtocolWitnessTable', this.popConformance());
      case 'l':
      case 'L': {
        const conf = this.popConformance();
        const t = this.pop('Type');
        return this.withChildren(c === 'l' ? 'LazyProtocolWitnessTableAccessor' : 'LazyProtocolWitnessTableCacheVariable', t, conf);
      }
      case 'a': return this.withChildren('ProtocolWitnessTableAccessor', this.popConformance());
      case 't': {
        const name = this.pop(DECL_NAMES);
        const conf = this.popConformance();
        return this.withChildren('AssociatedTypeMetadataAccessor', conf, name);
      }
      case 'T': {
        const proto = this.pop('Type');
        const path = this.popAssocTypePath();
        const conf = this.popConformance();
        return this.withChildren('AssociatedTypeWitnessTableAccessor', conf, path, proto);
      }
      case 'b': {
        const proto = this.pop('Type');
        const conf = this.popConformance();
        return this.withChildren('BaseWitnessTableAccessor', conf, proto);
      }
      case 'O': {
        const kinds: Record<string, string> = {
          B: 'OutlinedInitializeWithTakeNoValueWitness', C: 'OutlinedInitializeWithCopyNoValueWitness',
          D: 'OutlinedAssignWithTakeNoValueWitness', F: 'OutlinedAssignWithCopyNoValueWitness', H: 'OutlinedDestroyNoValueWitness',
          y: 'OutlinedCopy', e: 'OutlinedConsume', r: 'OutlinedRetain', s: 'OutlinedRelease', b: 'OutlinedInitializeWithTake',
          c: 'OutlinedInitializeWithCopy', d: 'OutlinedAssignWithTake', f: 'OutlinedAssignWithCopy', h: 'OutlinedDestroy',
          g: 'OutlinedEnumGetTag', i: 'OutlinedEnumTagStore', j: 'OutlinedEnumProjectDataForLoad',
        };
        const o = this.next();
        const kind = kinds[o];
        if (!kind) return null;
        const sig = this.pop('DependentGenericSignature');
        const t = this.pop('Type');
        if (o === 'i' || o === 'j') {
          const n = this.withChildren(kind, t);
          if (n && sig) n.children.push(sig);
          return this.add(n, this.indexNode());
        }
        const n = this.withChildren(kind, t);
        if (n && sig) n.children.push(sig);
        return n;
      }
      case 'Z':
      case 'z': {
        const list = this.node('GlobalVariableOnceDeclList');
        const vars: SwiftNode[] = [];
        while (this.pop('FirstElementMarker')) {
          const ident = this.pop(DECL_NAMES);
          if (!ident) return null;
          vars.push(ident);
        }
        list.children.push(...vars.reverse());
        const ctx = this.popContext();
        return this.withChildren(c === 'Z' ? 'GlobalVariableOnceFunction' : 'GlobalVariableOnceToken', ctx, list);
      }
      default: return null;
    }
  }

  private specialType(): N {
    const c = this.next();
    switch (c) {
      case 'E': return this.popFunctionType('NoEscapeFunctionType');
      case 'A': return this.popFunctionType('EscapingAutoClosureType');
      case 'f': return this.popFunctionType('ThinFunctionType');
      case 'K': return this.popFunctionType('AutoClosureType');
      case 'U': return this.popFunctionType('UncurriedFunctionType');
      case 'L': return this.popFunctionType('EscapingObjCBlock');
      case 'B': return this.popFunctionType('ObjCBlock');
      case 'C': return this.popFunctionType('CFunctionPointer');
      case 'z': {
        const k = this.next();
        if (k === 'B') return this.popFunctionType('ObjCBlock', true);
        if (k === 'C') return this.popFunctionType('CFunctionPointer', true);
        return null;
      }
      case 'o': return this.type(this.withChildren('Unowned', this.pop('Type')));
      case 'u': return this.type(this.withChildren('Unmanaged', this.pop('Type')));
      case 'w': return this.type(this.withChildren('Weak', this.pop('Type')));
      case 'b': return this.type(this.withChildren('SILBoxType', this.pop('Type')));
      case 'D': return this.type(this.withChildren('DynamicSelf', this.pop('Type')));
      case 'M':
      case 'm': {
        const repr = this.metatypeRepresentation();
        const t = this.pop('Type');
        return this.type(this.withChildren(c === 'M' ? 'Metatype' : 'ExistentialMetatype', repr, t));
      }
      case 'P': {
        const reqs = this.constrainedExistentialRequirements();
        const base = this.pop('Type');
        return this.type(this.withChildren('ConstrainedExistential', base, reqs));
      }
      case 'p': return this.type(this.withChildren('ExistentialMetatype', this.pop('Type')));
      case 'c': {
        const superclass = this.pop('Type');
        const protocols = this.protocolList();
        return this.type(this.withChildren('ProtocolListWithClass', protocols, superclass));
      }
      case 'l': return this.type(this.withChildren('ProtocolListWithAnyObject', this.protocolList()));
      case 'X':
      case 'x': {
        let sig: N = null;
        let args: N = null;
        if (c === 'X') {
          sig = this.pop('DependentGenericSignature');
          if (!sig) return null;
          args = this.popTypeList();
          if (!args) return null;
        }
        const fields = this.popTypeList();
        if (!fields) return null;
        const layout = this.node('SILBoxLayout');
        for (let field of fields.children) {
          let mutable = false;
          if (field.first.kind === 'InOut') {
            mutable = true;
            field = this.type(field.first.first)!;
          }
          const f = this.node(mutable ? 'SILBoxMutableField' : 'SILBoxImmutableField');
          f.children.push(field);
          layout.children.push(f);
        }
        const box = this.node('SILBoxTypeWithLayout');
        box.children.push(layout);
        if (sig && args) box.children.push(sig, args);
        return this.type(box);
      }
      case 'Y': return this.anyGenericType('OtherNominalType');
      case 'Z': {
        const types = this.popTypeList();
        const name = this.pop('Identifier');
        const parent = this.popContext();
        let anon: N = this.node('AnonymousContext');
        anon = this.add(anon, name);
        anon = this.add(anon, parent);
        anon = this.add(anon, types);
        return anon;
      }
      case 'e': return this.type(this.node('ErrorType'));
      case 'S': {
        switch (this.next()) {
          case 'q': return this.type(this.withChildren('SugaredOptional', this.pop('Type')));
          case 'a': return this.type(this.withChildren('SugaredArray', this.pop('Type')));
          case 'D': {
            const value = this.pop('Type');
            const key = this.pop('Type');
            return this.type(this.withChildren('SugaredDictionary', key, value));
          }
          case 'p': return this.type(this.withChildren('SugaredParen', this.pop('Type')));
          default: return null;
        }
      }
      default: return null;
    }
  }

  private metatypeRepresentation(): N {
    switch (this.next()) {
      case 't': return this.node('MetatypeRepresentation', '@thin');
      case 'T': return this.node('MetatypeRepresentation', '@thick');
      case 'o': return this.node('MetatypeRepresentation', '@objc_metatype');
      default: return null;
    }
  }

  private constrainedExistentialRequirements(): N {
    const list = this.node('ConstrainedExistentialRequirementList');
    let first = false;
    do {
      first = !!this.pop('FirstElementMarker');
      const r = this.pop(REQUIREMENTS);
      if (!r) return null;
      list.children.push(r);
    } while (!first);
    list.children.reverse();
    return list;
  }

  private typeAnnotation(): N {
    switch (this.next()) {
      case 'a': return this.node('AsyncAnnotation');
      case 'A': return this.node('IsolatedAnyFunctionType');
      case 'b': return this.node('ConcurrentFunctionType');
      case 'c': return this.withChildren('GlobalActorFunctionType', this.popTypeChild());
      case 'C': return this.node('NonIsolatedCallerFunctionType');
      case 'i': return this.type(this.withChildren('Isolated', this.popTypeChild()));
      case 'k': return this.type(this.withChildren('NoDerivative', this.popTypeChild()));
      case 'K': return this.withChildren('TypedThrowsAnnotation', this.popTypeChild());
      case 't': return this.type(this.withChildren('CompileTimeLiteral', this.popTypeChild()));
      case 'g': return this.type(this.withChildren('ConstValue', this.popTypeChild()));
      case 'T': return this.node('SendingResultFunctionType');
      case 'u': return this.type(this.withChildren('Sending', this.popTypeChild()));
      case 'j': {
        const k = this.next();
        if (!'dlfr'.includes(k) || k === '') return null;
        return this.node('DifferentiableFunctionType', undefined, k.charCodeAt(0));
      }
      default: return null;
    }
  }

  private functionEntity(): N {
    type Args = 'none' | 'typeAndName' | 'typeAndIndex' | 'index';
    let args: Args;
    let kind: string;
    switch (this.next()) {
      case 'D': args = 'none'; kind = 'Deallocator'; break;
      case 'd': args = 'none'; kind = 'Destructor'; break;
      case 'Z': args = 'none'; kind = 'IsolatedDeallocator'; break;
      case 'E': args = 'none'; kind = 'IVarDestroyer'; break;
      case 'e': args = 'none'; kind = 'IVarInitializer'; break;
      case 'i': args = 'none'; kind = 'Initializer'; break;
      case 'C': args = 'typeAndName'; kind = 'Allocator'; break;
      case 'c': args = 'typeAndName'; kind = 'Constructor'; break;
      case 'U': args = 'typeAndIndex'; kind = 'ExplicitClosure'; break;
      case 'u': args = 'typeAndIndex'; kind = 'ImplicitClosure'; break;
      case 'A': args = 'index'; kind = 'DefaultArgumentInitializer'; break;
      case 'm': return this.entity('Macro');
      case 'M': return this.macroExpansion();
      case 'p': return this.entity('GenericTypeParamDecl');
      case 'P': args = 'none'; kind = 'PropertyWrapperBackingInitializer'; break;
      case 'W': args = 'none'; kind = 'PropertyWrapperInitFromProjectedValue'; break;
      case 'F': args = 'none'; kind = 'PropertyWrappedFieldInitAccessor'; break;
      default: return null;
    }
    let nameOrIndex: N = null;
    let paramType: N = null;
    let labels: N = null;
    if (args === 'typeAndName') {
      nameOrIndex = this.pop('PrivateDeclName');
      paramType = this.pop('Type');
      labels = this.popFunctionParamLabels(paramType);
    } else if (args === 'typeAndIndex') {
      nameOrIndex = this.indexNode();
      paramType = this.pop('Type');
    } else if (args === 'index') nameOrIndex = this.indexNode();
    let entity = this.withChildren(kind, this.popContext());
    if (args === 'index') entity = this.add(entity, nameOrIndex);
    else if (args === 'typeAndName') {
      if (entity && labels) entity.children.push(labels);
      entity = this.add(entity, paramType);
      if (entity && nameOrIndex) entity.children.push(nameOrIndex);
    } else if (args === 'typeAndIndex') {
      entity = this.add(entity, nameOrIndex);
      entity = this.add(entity, paramType);
    }
    return entity;
  }

  private entity(kind: string): N {
    const t = this.pop('Type');
    const labels = this.popFunctionParamLabels(t);
    const name = this.pop(DECL_NAMES);
    const ctx = this.popContext();
    return labels ? this.withChildren(kind, ctx, name, labels, t) : this.withChildren(kind, ctx, name, t);
  }

  private variable(): N {
    return this.accessor(this.entity('Variable'));
  }

  private subscript(): N {
    const privateName = this.pop('PrivateDeclName');
    const t = this.pop('Type');
    const labels = this.popFunctionParamLabels(t);
    const ctx = this.popContext();
    let sub: N = this.node('Subscript');
    sub = this.add(sub, ctx);
    if (sub && labels) sub.children.push(labels);
    sub = this.add(sub, t);
    if (sub && privateName) sub.children.push(privateName);
    return this.accessor(sub);
  }

  private accessor(child: N): N {
    let kind: string;
    switch (this.next()) {
      case 'm': kind = 'MaterializeForSet'; break;
      case 's': kind = 'Setter'; break;
      case 'g': kind = 'Getter'; break;
      case 'G': kind = 'GlobalGetter'; break;
      case 'w': kind = 'WillSet'; break;
      case 'W': kind = 'DidSet'; break;
      case 'r': kind = 'ReadAccessor'; break;
      case 'y': kind = 'Read2Accessor'; break;
      case 'M': kind = 'ModifyAccessor'; break;
      case 'x': kind = 'Modify2Accessor'; break;
      case 'i': kind = 'InitAccessor'; break;
      case 'a': {
        const k = ({ O: 'OwningMutableAddressor', o: 'NativeOwningMutableAddressor', P: 'NativePinningMutableAddressor', u: 'UnsafeMutableAddressor' } as Record<string, string>)[this.next()];
        if (!k) return null;
        kind = k;
        break;
      }
      case 'l': {
        const k = ({ O: 'OwningAddressor', o: 'NativeOwningAddressor', p: 'NativePinningAddressor', u: 'UnsafeAddressor' } as Record<string, string>)[this.next()];
        if (!k) return null;
        kind = k;
        break;
      }
      case 'p': return child;
      default: return null;
    }
    return this.withChildren(kind, child);
  }

  private macroExpansion(): N {
    const kinds: Record<string, [string, boolean, boolean]> = {
      a: ['AccessorAttachedMacroExpansion', true, false], r: ['MemberAttributeAttachedMacroExpansion', true, false],
      m: ['MemberAttachedMacroExpansion', true, false], p: ['PeerAttachedMacroExpansion', true, false],
      c: ['ConformanceAttachedMacroExpansion', true, false], e: ['ExtensionAttachedMacroExpansion', true, false],
      q: ['PreambleAttachedMacroExpansion', true, false], b: ['BodyAttachedMacroExpansion', true, false],
      f: ['FreestandingMacroExpansion', false, true], u: ['MacroExpansionUniqueName', false, false],
    };
    const entry = kinds[this.next()];
    if (!entry) return null;
    const [kind, attached, freestanding] = entry;
    const macroName = this.pop('Identifier');
    const privateDiscriminator = freestanding ? this.pop('PrivateDeclName') : null;
    const attachedName = attached ? this.pop(DECL_NAMES) : null;
    const ctx = this.pop(MACRO_EXPANSIONS) ?? this.popContext();
    const discriminator = this.indexNode();
    const result = attached ? this.withChildren(kind, ctx, attachedName, macroName, discriminator) : this.withChildren(kind, ctx, macroName, discriminator);
    if (result && privateDiscriminator) result.children.push(privateDiscriminator);
    return result;
  }

  private valueWitness(): N {
    const code = this.next() + this.next();
    const name = VALUE_WITNESSES[code];
    if (!name) return null;
    const vw = this.node('ValueWitness');
    vw.children.push(this.node('Index', name));
    return this.add(vw, this.pop('Type'));
  }

  private thunkOrSpecialization(): N {
    const c = this.next();
    switch (c) {
      case 'T': {
        const k = this.next();
        if (k === 'I') return this.withChildren('SILThunkIdentity', this.popEntity());
        if (k === 'H') return this.withChildren('SILThunkHopToMainActorIfNeeded', this.popEntity());
        return null;
      }
      case 'c': return this.withChildren('CurryThunk', this.popEntity());
      case 'j': return this.withChildren('DispatchThunk', this.popEntity());
      case 'q': return this.withChildren('MethodDescriptor', this.popEntity());
      case 'o': return this.node('ObjCAttribute');
      case 'O': return this.node('NonObjCAttribute');
      case 'D': return this.node('DynamicAttribute');
      case 'd': return this.node('DirectMethodReferenceAttribute');
      case 'E': return this.node('DistributedThunk');
      case 'F': return this.node('DistributedAccessor');
      case 'a': return this.node('PartialApplyObjCForwarder');
      case 'A': return this.node('PartialApplyForwarder');
      case 'm': return this.node('MergedFunction');
      case 'X': return this.node('DynamicallyReplaceableFunctionVar');
      case 'x': return this.node('DynamicallyReplaceableFunctionKey');
      case 'I': return this.node('DynamicallyReplaceableFunctionImpl');
      case 'Y':
      case 'Q': return this.withChildren(c === 'Q' ? 'AsyncAwaitResumePartialFunction' : 'AsyncSuspendResumePartialFunction', this.indexNode());
      case 'C': return this.withChildren('CoroutineContinuationPrototype', this.pop('Type'));
      case 'z':
      case 'Z': {
        const flag = this.indexNode();
        if (!flag) return null;
        const sig = this.pop('DependentGenericSignature');
        const result = this.pop('Type');
        const impl = this.pop('Type');
        const n = this.withChildren(c === 'z' ? 'ObjCAsyncCompletionHandlerImpl' : 'PredefinedObjCAsyncCompletionHandlerImpl', impl, result, flag);
        if (n && sig) n.children.push(sig);
        return n;
      }
      case 'V': {
        const base = this.popEntity();
        const derived = this.popEntity();
        return this.withChildren('VTableThunk', derived, base);
      }
      case 'W': {
        const entity = this.popEntity();
        const conf = this.popConformance();
        return this.withChildren('ProtocolWitness', conf, entity);
      }
      case 'S': return this.withChildren('ProtocolSelfConformanceWitness', this.popEntity());
      case 'R':
      case 'r':
      case 'y': {
        const kind = c === 'R' ? 'ReabstractionThunkHelper' : c === 'y' ? 'ReabstractionThunkHelperWithSelf' : 'ReabstractionThunk';
        const thunk: N = this.node(kind);
        this.addIf(thunk, this.pop('DependentGenericSignature'));
        if (kind === 'ReabstractionThunkHelperWithSelf') this.addIf(thunk, this.pop('Type'));
        this.addIf(thunk, this.pop('Type'));
        this.addIf(thunk, this.pop('Type'));
        return thunk;
      }
      case 'g': return this.genericSpecialization('GenericSpecialization');
      case 'G': return this.genericSpecialization('GenericSpecializationNotReAbstracted');
      case 'B': return this.genericSpecialization('GenericSpecializationInResilienceDomain');
      case 's': return this.genericSpecialization('GenericSpecializationPrespecialized');
      case 'i': return this.genericSpecialization('InlinedGenericFunction');
      case 't': return this.genericSpecializationWithDroppedArguments();
      case 'p':
      case 'P': {
        const spec = this.specAttributes(c === 'p' ? 'GenericPartialSpecialization' : 'GenericPartialSpecializationNotReAbstracted');
        return this.add(spec, this.withChildren('GenericSpecializationParam', this.pop('Type')));
      }
      case 'f': return this.functionSpecialization();
      case 'K':
      case 'k': {
        const kind = c === 'K' ? 'KeyPathGetterThunkHelper' : 'KeyPathSetterThunkHelper';
        const serialized = this.nextIf('q');
        const types: SwiftNode[] = [];
        let n = this.pop();
        if (!n || n.kind !== 'Type') return null;
        do {
          types.push(n);
          n = this.pop();
        } while (n && n.kind === 'Type');
        if (!n) return null;
        let result: N;
        if (n.kind === 'DependentGenericSignature') {
          const decl = this.pop();
          if (!decl) return null;
          result = this.withChildren(kind, decl, n);
        } else result = this.withChildren(kind, n);
        result!.children.push(...types.reverse());
        if (serialized) result!.children.push(this.node('IsSerialized'));
        return result;
      }
      case 'l': return this.withChildren('AssociatedTypeDescriptor', this.popAssocTypeName());
      case 'L': return this.withChildren('ProtocolRequirementsBaseDescriptor', this.popProtocol());
      case 'M': return this.withChildren('DefaultAssociatedTypeMetadataAccessor', this.popAssocTypeName());
      case 'n':
      case 'N': {
        const requirement = this.popProtocol();
        const path = this.popAssocTypePath();
        const proto = this.pop('Type');
        return this.withChildren(c === 'n' ? 'AssociatedConformanceDescriptor' : 'DefaultAssociatedConformanceAccessor', proto, path, requirement);
      }
      case 'b': {
        const requirement = this.popProtocol();
        const proto = this.pop('Type');
        return this.withChildren('BaseConformanceDescriptor', proto, requirement);
      }
      case 'H':
      case 'h': {
        const kind = c === 'H' ? 'KeyPathEqualsThunkHelper' : 'KeyPathHashThunkHelper';
        const serialized = this.nextIf('q');
        let sig: N = null;
        const types: SwiftNode[] = [];
        const n = this.pop();
        if (!n) return null;
        if (n.kind === 'DependentGenericSignature') sig = n;
        else if (n.kind === 'Type') types.push(n);
        else return null;
        for (let t = this.pop(); t; t = this.pop()) {
          if (t.kind !== 'Type') return null;
          types.push(t);
        }
        const result = this.node(kind);
        result.children.push(...types.reverse());
        if (sig) result.children.push(sig);
        if (serialized) result.children.push(this.node('IsSerialized'));
        return result;
      }
      case 'v': {
        const i = this.index();
        if (i < 0) return null;
        if (this.nextIf('r')) return this.node('OutlinedReadOnlyObject', undefined, i);
        return this.node('OutlinedVariable', undefined, i);
      }
      case 'e': {
        const params = this.bridgedMethodParams();
        if (!params) return null;
        return this.node('OutlinedBridgedMethod', params);
      }
      case 'u': return this.node('AsyncFunctionPointer');
      case 'U': {
        const actor = this.pop('Type');
        if (!actor) return null;
        const reabstraction = this.pop();
        if (!reabstraction) return null;
        return this.withChildren('ReabstractionThunkHelperWithGlobalActor', reabstraction, actor);
      }
      case 'w': {
        const k = this.next();
        if (k === 'b') return this.node('BackDeploymentThunk');
        if (k === 'B') return this.node('BackDeploymentFallback');
        if (k === 'S') return this.node('HasSymbolQuery');
        return null;
      }
      default: return null;
    }
  }

  private bridgedMethodParams(): string {
    if (this.nextIf('_')) return '';
    let out = '';
    const kind = this.next();
    if (!'nbgo'.includes(kind) || kind === '') return '';
    out += kind;
    while (!this.nextIf('_')) {
      const k = this.next();
      if (!'nbgo'.includes(k) || k === '') return '';
      out += k;
    }
    return out;
  }

  private specAttributes(kind: string): N {
    const metatypesRemoved = this.nextIf('m');
    const serialized = this.nextIf('q');
    const asyncRemoved = this.nextIf('a');
    const pass = this.next().charCodeAt(0) - 48;
    if (!(pass >= 0 && pass < 10)) return null;
    const spec = this.node(kind);
    if (metatypesRemoved) spec.children.push(this.node('MetatypeParamsRemoved'));
    if (serialized) spec.children.push(this.node('IsSerialized'));
    if (asyncRemoved) spec.children.push(this.node('AsyncRemoved'));
    spec.children.push(this.node('SpecializationPassID', undefined, pass));
    return spec;
  }

  private genericSpecialization(kind: string, dropped: SwiftNode[] = []): N {
    const spec = this.specAttributes(kind);
    if (!spec) return null;
    spec.children.push(...dropped);
    const list = this.popTypeList();
    if (!list) return null;
    for (const t of list.children) spec.children.push(this.withChildren('GenericSpecializationParam', t)!);
    return spec;
  }

  private genericSpecializationWithDroppedArguments(): N {
    this.back();
    const dropped: SwiftNode[] = [];
    while (this.nextIf('t')) {
      const n = this.natural();
      dropped.push(this.node('DroppedArgument', undefined, n < 0 ? 0 : n + 1));
    }
    const c = this.next();
    const kinds: Record<string, string> = {
      g: 'GenericSpecialization', G: 'GenericSpecializationNotReAbstracted', B: 'GenericSpecializationInResilienceDomain',
      s: 'GenericSpecializationPrespecialized', i: 'InlinedGenericFunction',
    };
    const kind = kinds[c];
    if (!kind) return null;
    return this.genericSpecialization(kind, dropped);
  }

  private functionSpecialization(): N {
    let spec = this.specAttributes('FunctionSignatureSpecialization');
    while (spec && !this.nextIf('_')) {
      if (this.pos >= this.s.length) return null;
      spec = this.add(spec, this.funcSpecParam('FunctionSignatureSpecializationParam'));
    }
    if (!this.nextIf('n')) spec = this.add(spec, this.funcSpecParam('FunctionSignatureSpecializationReturn'));
    if (!spec) return null;
    for (let i = spec.count - 1; i >= 0; i--) {
      const param = spec.child(i);
      if (param.kind !== 'FunctionSignatureSpecializationParam' || !param.count) continue;
      const kindNode = param.first;
      const kind = kindNode.index!;
      const closure = kind === FSS.ClosureProp || kind === FSS.ClosurePropPreviousArg || kind === FSS.ClosurePropEscaping;
      if (!closure && ![FSS.ConstantPropFunction, FSS.ConstantPropGlobal, FSS.ConstantPropString, FSS.ConstantPropKeyPath].includes(kind)) continue;
      const types: SwiftNode[] = [];
      for (let t = this.pop('Type'); t; t = this.pop('Type')) {
        if (!closure && kind !== FSS.ConstantPropKeyPath) return null;
        types.push(t);
      }
      const name = this.pop('Identifier');
      if (!name) return null;
      let text = name.text!;
      if (kind === FSS.ConstantPropString && text.startsWith('_')) text = text.slice(1);
      const added = [...types, this.node('FunctionSignatureSpecializationParamPayload', text)];
      param.children.push(...added.reverse());
    }
    return spec;
  }

  private funcSpecParam(kind: string): N {
    const param = this.node(kind);
    const withKind = (k: number) => {
      param.children.push(this.node('FunctionSignatureSpecializationParamKind', undefined, k));
      return param;
    };
    switch (this.next()) {
      case 'n': return param;
      case 'c': return withKind(FSS.ClosureProp);
      case 'E': return withKind(FSS.ClosurePropEscaping);
      case 'C': {
        withKind(FSS.ClosurePropPreviousArg);
        const n = this.natural();
        if (n < 0) return null;
        param.children.push(this.node('FunctionSignatureSpecializationParamPayload', String(n)));
        return param;
      }
      case 'p': {
        switch (this.next()) {
          case 'f': return withKind(FSS.ConstantPropFunction);
          case 'g': return withKind(FSS.ConstantPropGlobal);
          case 'i':
          case 'd': {
            this.back();
            const k = this.next() === 'i' ? FSS.ConstantPropInteger : FSS.ConstantPropFloat;
            withKind(k);
            let digits = '';
            if (this.peek() === '-') digits += this.next();
            while (isDigit(this.peek())) digits += this.next();
            if (!digits) return null;
            param.children.push(this.node('FunctionSignatureSpecializationParamPayload', digits));
            return param;
          }
          case 's': {
            const encoding = ({ b: 'u8', w: 'u16', c: 'objc' } as Record<string, string>)[this.next()];
            if (!encoding) return null;
            withKind(FSS.ConstantPropString);
            param.children.push(this.node('FunctionSignatureSpecializationParamPayload', encoding));
            return param;
          }
          case 'k': return withKind(FSS.ConstantPropKeyPath);
          default: return null;
        }
      }
      case 'e': {
        let v = FSS.ExistentialToGeneric;
        if (this.nextIf('D')) v |= FSS.Dead;
        if (this.nextIf('G')) v |= FSS.OwnedToGuaranteed;
        if (this.nextIf('O')) v |= FSS.GuaranteedToOwned;
        if (this.nextIf('X')) v |= FSS.SROA;
        return withKind(v);
      }
      case 'd': {
        let v = FSS.Dead;
        if (this.nextIf('G')) v |= FSS.OwnedToGuaranteed;
        if (this.nextIf('O')) v |= FSS.GuaranteedToOwned;
        if (this.nextIf('X')) v |= FSS.SROA;
        return withKind(v);
      }
      case 'g': {
        let v = FSS.OwnedToGuaranteed;
        if (this.nextIf('X')) v |= FSS.SROA;
        return withKind(v);
      }
      case 'o': {
        let v = FSS.GuaranteedToOwned;
        if (this.nextIf('X')) v |= FSS.SROA;
        return withKind(v);
      }
      case 'x': return withKind(FSS.SROA);
      case 'i': return withKind(FSS.BoxToValue);
      case 's': return withKind(FSS.BoxToStack);
      case 'r': return withKind(FSS.InOutToOut);
      default: return null;
    }
  }

  private implFunctionType(): N {
    let type: N = this.node('ImplFunctionType');
    if (this.nextIf('s')) {
      const lists: SwiftNode[] = [];
      const { ok, retro } = this.boundGenerics(lists);
      if (!ok) return null;
      const sig = this.pop('DependentGenericSignature');
      if (!sig) return null;
      const subs = this.node('ImplPatternSubstitutions');
      subs.children.push(sig, lists[0]!);
      if (retro) subs.children.push(retro);
      type.children.push(subs);
    }
    if (this.nextIf('I')) {
      const lists: SwiftNode[] = [];
      const { ok, retro } = this.boundGenerics(lists);
      if (!ok) return null;
      const subs = this.node('ImplInvocationSubstitutions');
      subs.children.push(lists[0]!);
      if (retro) subs.children.push(retro);
      type.children.push(subs);
    }
    let sig = this.pop('DependentGenericSignature');
    if (sig && this.nextIf('P')) sig = this.changeKind(sig, 'DependentPseudogenericSignature');
    if (this.nextIf('e')) type.children.push(this.node('ImplEscaping'));
    if (this.nextIf('A')) type.children.push(this.node('ImplErasedIsolation'));
    if ('dlfr'.includes(this.peek()) && this.peek() !== '') type.children.push(this.node('ImplDifferentiabilityKind', this.next()));
    const callee = ({ y: '@callee_unowned', g: '@callee_guaranteed', x: '@callee_owned', t: '@convention(thin)' } as Record<string, string>)[this.next()];
    if (!callee) return null;
    type.children.push(this.node('ImplConvention', callee));
    let conv: string | undefined;
    let clang = false;
    const f = this.next();
    switch (f) {
      case 'B': conv = 'block'; break;
      case 'C': conv = 'c'; break;
      case 'z': {
        const k = this.next();
        if (k === 'B') { clang = true; conv = 'block'; }
        else if (k === 'C') { clang = true; conv = 'c'; }
        else { this.back(); this.back(); }
        break;
      }
      case 'M': conv = 'method'; break;
      case 'O': conv = 'objc_method'; break;
      case 'K': conv = 'closure'; break;
      case 'W': conv = 'witness_method'; break;
      default: this.back(); break;
    }
    if (conv) {
      const attr = this.node('ImplFunctionConvention');
      attr.children.push(this.node('ImplFunctionConventionName', conv));
      if (clang) {
        const ct = this.clangType();
        if (!ct) return null;
        attr.children.push(ct);
      }
      type.children.push(attr);
    }
    const coro = this.nextIf('A') ? '@yield_once' : this.nextIf('I') ? '@yield_once_2' : this.nextIf('G') ? '@yield_many' : undefined;
    if (coro) type.children.push(this.node('ImplCoroutineKind', coro));
    if (this.nextIf('h')) type.children.push(this.node('ImplFunctionAttribute', '@Sendable'));
    if (this.nextIf('H')) type.children.push(this.node('ImplFunctionAttribute', '@async'));
    if (this.nextIf('T')) type.children.push(this.node('ImplSendingResult'));
    if (sig) type.children.push(sig);
    let count = 0;
    for (let p = this.implParam('ImplParameter'); p; p = this.implParam('ImplParameter')) {
      type = this.add(type, p);
      const diff = this.implDifferentiability();
      if (diff) p.children.push(diff);
      if (this.nextIf('T')) p.children.push(this.node('ImplParameterSending', 'sending'));
      if (this.nextIf('I')) p.children.push(this.node('ImplParameterIsolated', 'isolated'));
      if (this.nextIf('L')) p.children.push(this.node('ImplParameterImplicitLeading', 'sil_implicit_leading_param'));
      count++;
    }
    for (let r = this.implResult('ImplResult'); r; r = this.implResult('ImplResult')) {
      type = this.add(type, r);
      const diff = this.implDifferentiability();
      if (diff) r.children.push(diff);
      count++;
    }
    while (this.nextIf('Y')) {
      const y = this.implParam('ImplYield');
      if (!y) return null;
      type = this.add(type, y);
      count++;
    }
    if (this.nextIf('z')) {
      const e = this.implResult('ImplErrorResult');
      if (!e) return null;
      type = this.add(type, e);
      count++;
    }
    if (!this.nextIf('_') || !type) return null;
    for (let i = 0; i < count; i++) {
      const t = this.pop('Type');
      if (!t) return null;
      type.child(type.count - i - 1).children.push(t);
    }
    return this.type(type);
  }

  private implDifferentiability(): N {
    if (this.nextIf('w')) return this.node('ImplParameterResultDifferentiability', '@noDerivative');
    return null;
  }

  private implParam(kind: string): N {
    const attr = ({
      i: '@in', c: '@in_constant', l: '@inout', b: '@inout_aliasable', n: '@in_guaranteed', X: '@in_cxx', x: '@owned',
      g: '@guaranteed', e: '@deallocating', y: '@unowned', v: '@pack_owned', p: '@pack_guaranteed', m: '@pack_inout',
    } as Record<string, string>)[this.next()];
    if (!attr) {
      this.back();
      return null;
    }
    return this.withChildren(kind, this.node('ImplConvention', attr));
  }

  private implResult(kind: string): N {
    const attr = ({ r: '@out', o: '@owned', d: '@unowned', u: '@unowned_inner_pointer', a: '@autoreleased', k: '@pack_out' } as Record<string, string>)[this.next()];
    if (!attr) {
      this.back();
      return null;
    }
    return this.withChildren(kind, this.node('ImplConvention', attr));
  }
}

function isProtocolNode(t: SwiftNode): boolean {
  const k = t.kind === 'Type' ? t.children[0]?.kind : t.kind;
  return k === 'Protocol' || k === 'ProtocolSymbolicReference' || k === 'ObjectiveCProtocolSymbolicReference';
}

/** Punycode as Swift encodes identifiers that are not ASCII: `_` is the delimiter, digits are a–z then A–J. */
function punycode(input: string): string | null {
  const base = 36;
  const tMin = 1;
  const tMax = 26;
  const skew = 38;
  const damp = 700;
  let n = 128;
  let i = 0;
  let bias = 72;
  const out: number[] = [];
  const delimiter = input.lastIndexOf('_');
  let pos = 0;
  if (delimiter >= 0) {
    for (let k = 0; k < delimiter; k++) {
      const c = input.charCodeAt(k);
      if (c >= 0x80) return null;
      out.push(c);
    }
    pos = delimiter + 1;
  }
  const digit = (c: string): number => {
    if (c >= 'a' && c <= 'z') return c.charCodeAt(0) - 97;
    if (c >= 'A' && c <= 'J') return c.charCodeAt(0) - 65 + 26;
    return -1;
  };
  const adapt = (delta: number, points: number, first: boolean) => {
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / points);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) {
      delta = Math.floor(delta / (base - tMin));
      k += base;
    }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  while (pos < input.length) {
    const oldI = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (pos >= input.length) return null;
      const d = digit(input[pos++]!);
      if (d < 0) return null;
      i += d * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (d < t) break;
      w *= base - t;
    }
    bias = adapt(i - oldI, out.length + 1, oldI === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    // Swift maps the surrogate range above 0xD800 to keep invalid code points out.
    if (n >= 0xd800 && n <= 0xd880) n -= 0xd800;
    if (n > 0x10ffff) return null;
    out.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...out);
}

/** The tree of a symbol (null when it does not parse). */
export function parseSwift(symbol: string): SwiftNode | null {
  try {
    return new Demangler(symbol).demangleSymbol();
  } catch (err) {
    if (err instanceof Bad) return null;
    throw err;
  }
}

/** The tree as `swift-demangle --tree-only` prints it, for comparing the two. */
export function swiftTree(n: SwiftNode, depth = 0): string {
  let line = `${' '.repeat(depth * 2)}kind=${n.kind}`;
  if (n.text !== undefined) line += `, text="${n.text}"`;
  else if (n.index !== undefined) line += `, index=${n.index}`;
  return [line, ...n.children.map((c) => swiftTree(c, depth + 1))].join('\n');
}

/* ------------------------------------------------------------------ *
 * Printing
 * ------------------------------------------------------------------ */

interface Options {
  synthesizeSugarOnTypes: boolean;
  displayModuleNames: boolean;
  displayExtensionContexts: boolean;
  displayUnmangledSuffix: boolean;
  displayGenericSpecializations: boolean;
  displayProtocolConformances: boolean;
  displayWhereClauses: boolean;
  displayEntityTypes: boolean;
  shortenPartialApply: boolean;
  shortenThunk: boolean;
  shortenValueWitness: boolean;
  showPrivateDiscriminators: boolean;
  showFunctionArgumentTypes: boolean;
  showAsyncResumePartial: boolean;
}

/** What `swift-demangle` prints by default. */
const FULL: Options = {
  synthesizeSugarOnTypes: true,
  displayModuleNames: true, displayExtensionContexts: true, displayUnmangledSuffix: true, displayGenericSpecializations: true,
  displayProtocolConformances: true, displayWhereClauses: true, displayEntityTypes: true, shortenPartialApply: false,
  shortenThunk: false, shortenValueWitness: false, showPrivateDiscriminators: true, showFunctionArgumentTypes: true,
  showAsyncResumePartial: true,
};
/** What `swift-demangle --simplified` prints. */
const SIMPLIFIED: Options = {
  synthesizeSugarOnTypes: true,
  displayModuleNames: false, displayExtensionContexts: false, displayUnmangledSuffix: false, displayGenericSpecializations: false,
  displayProtocolConformances: false, displayWhereClauses: false, displayEntityTypes: false, shortenPartialApply: true,
  shortenThunk: true, shortenValueWitness: true, showPrivateDiscriminators: false, showFunctionArgumentTypes: false,
  showAsyncResumePartial: false,
};

type TypePrinting = 'none' | 'colon' | 'function';

/** Prefixes that are printed before their one child, and nothing else. */
const PREFIXED: Record<string, string> = {
  CurryThunk: 'curry thunk of ', DispatchThunk: 'dispatch thunk of ', MethodDescriptor: 'method descriptor for ',
  MethodLookupFunction: 'method lookup function for ', ObjCMetadataUpdateFunction: 'ObjC metadata update function for ',
  ObjCResilientClassStub: 'ObjC resilient class stub for ', FullObjCResilientClassStub: 'full ObjC resilient class stub for ',
  OutlinedCopy: 'outlined copy of ', OutlinedConsume: 'outlined consume of ', OutlinedRetain: 'outlined retain of ',
  OutlinedRelease: 'outlined release of ', OutlinedInitializeWithTake: 'outlined init with take of ',
  OutlinedInitializeWithCopy: 'outlined init with copy of ', OutlinedAssignWithTake: 'outlined assign with take of ',
  OutlinedAssignWithCopy: 'outlined assign with copy of ', OutlinedDestroy: 'outlined destroy of ',
  OutlinedInitializeWithTakeNoValueWitness: 'outlined init with take of ', OutlinedInitializeWithCopyNoValueWitness: 'outlined init with copy of ',
  OutlinedAssignWithTakeNoValueWitness: 'outlined assign with take of ', OutlinedAssignWithCopyNoValueWitness: 'outlined assign with copy of ',
  OutlinedDestroyNoValueWitness: 'outlined destroy of ', OutlinedEnumGetTag: 'outlined enum get tag of ',
  OutlinedEnumTagStore: 'outlined enum tag store of ', OutlinedEnumProjectDataForLoad: 'outlined enum project data for load of ',
  ProtocolSelfConformanceWitness: 'protocol self-conformance witness for ',
  ProtocolSelfConformanceWitnessTable: 'protocol self-conformance witness table for ', ProtocolWitnessTable: 'protocol witness table for ',
  ProtocolWitnessTablePattern: 'protocol witness table pattern for ', GenericProtocolWitnessTable: 'generic protocol witness table for ',
  GenericProtocolWitnessTableInstantiationFunction: 'instantiation function for generic protocol witness table for ',
  ResilientProtocolWitnessTable: 'resilient protocol witness table for ', ProtocolWitnessTableAccessor: 'protocol witness table accessor for ',
  EnumCase: 'enum case for ', ValueWitnessTable: 'value witness table for ', ProtocolConformanceDescriptor: 'protocol conformance descriptor for ',
  ProtocolDescriptor: 'protocol descriptor for ', ProtocolRequirementsBaseDescriptor: 'protocol requirements base descriptor for ',
  FullTypeMetadata: 'full type metadata for ', TypeMetadata: 'type metadata for ', TypeMetadataAccessFunction: 'type metadata accessor for ',
  TypeMetadataInstantiationCache: 'type metadata instantiation cache for ', TypeMetadataInstantiationFunction: 'type metadata instantiation function for ',
  TypeMetadataSingletonInitializationCache: 'type metadata singleton initialization cache for ',
  TypeMetadataCompletionFunction: 'type metadata completion function for ', TypeMetadataDemanglingCache: 'demangling cache variable for type metadata for ',
  TypeMetadataLazyCache: 'lazy cache variable for type metadata for ', TypeMetadataMangledNameRef: 'mangled name ref for type metadata for ', Metaclass: 'metaclass for ', NominalTypeDescriptor: 'nominal type descriptor for ',
  NominalTypeDescriptorRecord: 'nominal type descriptor runtime record for ', OpaqueTypeDescriptor: 'opaque type descriptor for ',
  OpaqueTypeDescriptorRecord: 'opaque type descriptor runtime record for ', OpaqueTypeDescriptorAccessor: 'opaque type descriptor accessor for ',
  OpaqueTypeDescriptorAccessorImpl: 'opaque type descriptor accessor impl for ', OpaqueTypeDescriptorAccessorKey: 'opaque type descriptor accessor key for ',
  OpaqueTypeDescriptorAccessorVar: 'opaque type descriptor accessor var for ', PropertyDescriptor: 'property descriptor for ',
  ClassMetadataBaseOffset: 'class metadata base offset for ', GenericTypeMetadataPattern: 'generic type metadata pattern for ',
  ReflectionMetadataBuiltinDescriptor: 'reflection metadata builtin descriptor ', ReflectionMetadataFieldDescriptor: 'reflection metadata field descriptor ',
  ReflectionMetadataAssocTypeDescriptor: 'reflection metadata associated type descriptor ',
  ReflectionMetadataSuperclassDescriptor: 'reflection metadata superclass descriptor ',
  ProtocolConformanceDescriptorRecord: 'protocol conformance descriptor runtime record for ', ProtocolDescriptorRecord: 'protocol descriptor runtime record for ',
  ProtocolSelfConformanceDescriptor: 'protocol self-conformance descriptor for ', CanonicalSpecializedGenericMetaclass: 'specialized generic metaclass for ',
  CanonicalSpecializedGenericTypeMetadataAccessFunction: 'canonical specialized generic type metadata accessor for ',
  NoncanonicalSpecializedGenericTypeMetadata: 'noncanonical specialized generic type metadata for ',
  NoncanonicalSpecializedGenericTypeMetadataCache: 'cache variable for noncanonical specialized generic type metadata for ',
  CanonicalPrespecializedGenericTypeCachingOnceToken: 'flag for loading of canonical specialized generic type metadata for ',
  MetadataInstantiationCache: 'metadata instantiation cache for ', Uniquable: 'uniquable ', AssociatedTypeDescriptor: 'associated type descriptor for ',
  DefaultAssociatedTypeMetadataAccessor: 'default associated type metadata accessor for ', ExtensionDescriptor: 'extension descriptor ',
  ModuleDescriptor: 'module descriptor ', CoroutineContinuationPrototype: 'coroutine continuation prototype for ',
  SILThunkIdentity: 'identity thunk of ', SILThunkHopToMainActorIfNeeded: 'hop to main actor thunk of ',
  Shared: '__shared ', Owned: '__owned ', InOut: 'inout ', Isolated: 'isolated ', Sending: 'sending ', CompileTimeLiteral: '_const ',
  ConstValue: '@const ', NoDerivative: '@noDerivative ', Weak: 'weak ', Unowned: 'unowned ', Unmanaged: 'unowned(unsafe) ', SILBoxType: '@box ',
};

/** Accessors: the word printed after the variable or subscript. */
const ACCESSORS: Record<string, string> = {
  Getter: 'getter', Setter: 'setter', MaterializeForSet: 'materializeForSet', WillSet: 'willset', DidSet: 'didset', ReadAccessor: 'read',
  Read2Accessor: 'yielding_borrow', ModifyAccessor: 'modify', Modify2Accessor: 'yielding_mutate', InitAccessor: 'init', UnsafeAddressor: 'unsafeAddressor',
  UnsafeMutableAddressor: 'unsafeMutableAddressor', OwningAddressor: 'owningAddressor', OwningMutableAddressor: 'owningMutableAddressor',
  NativeOwningAddressor: 'nativeOwningAddressor', NativeOwningMutableAddressor: 'nativeOwningMutableAddressor',
  NativePinningAddressor: 'nativePinningAddressor', NativePinningMutableAddressor: 'nativePinningMutableAddressor', GlobalGetter: 'getter',
};

const SIMPLE_TYPES = new Set([
  'AssociatedType', 'AssociatedTypeRef', 'BoundGenericClass', 'BoundGenericEnum', 'BoundGenericStructure', 'BoundGenericProtocol',
  'BoundGenericOtherNominalType', 'BoundGenericTypeAlias', 'BoundGenericFunction', 'BuiltinTypeName', 'BuiltinTupleType', 'Class',
  'DependentGenericType', 'DependentMemberType', 'DependentGenericParamType', 'DynamicSelf', 'Enum', 'ErrorType',
  'ExistentialMetatype', 'Metatype', 'MetatypeRepresentation', 'Module', 'Tuple', 'Pack', 'ConstrainedExistentialRequirementList',
  'ConstrainedExistentialSelf', 'Protocol', 'ProtocolSymbolicReference', 'ReturnType', 'SILBoxType', 'SILBoxTypeWithLayout',
  'Structure', 'OtherNominalType', 'TupleElementName', 'TypeAlias', 'TypeList', 'LabelList', 'TypeSymbolicReference',
  'SugaredOptional', 'SugaredArray', 'SugaredDictionary', 'SugaredParen',
]);

const genericParameterName = (depth: number, index: number): string => {
  let name = '';
  do {
    name += String.fromCharCode(65 + (index % 26));
    index = Math.floor(index / 26);
  } while (index);
  return depth ? `${name}${depth}` : name;
};

class Printer {
  out = '';
  private specializationPrefixPrinted = false;
  constructor(private readonly o: Options) {}

  printChildren(n: SwiftNode, depth: number, separator?: string): void {
    n.children.forEach((c, i) => {
      if (i && separator) this.out += separator;
      this.print(c, depth + 1);
    });
  }

  private isSimpleType(n: SwiftNode): boolean {
    if (n.kind === 'Type') return this.isSimpleType(n.first);
    if (n.kind === 'ProtocolList') return n.first.count <= 1;
    if (n.kind === 'ProtocolListWithAnyObject') return n.first.first.count === 0;
    return SIMPLE_TYPES.has(n.kind);
  }

  private printWithParens(t: SwiftNode, depth: number): void {
    const parens = !this.isSimpleType(t);
    if (parens) this.out += '(';
    this.print(t, depth + 1);
    if (parens) this.out += ')';
  }

  private needSpaceBeforeType(t: SwiftNode): boolean {
    if (t.kind === 'Type') return this.needSpaceBeforeType(t.first);
    return !['FunctionType', 'NoEscapeFunctionType', 'UncurriedFunctionType', 'DependentGenericType'].includes(t.kind);
  }

  print(n: SwiftNode, depth: number, asPrefix = false): N {
    if (depth > 768) throw new Bad();
    const k = n.kind;
    const prefixed = PREFIXED[k];
    if (prefixed !== undefined) {
      this.out += prefixed;
      this.print(n.child(0), depth + 1);
      // An outlined copy or consume names the generic signature it was made under.
      if ((k === 'OutlinedCopy' || k === 'OutlinedConsume') && n.count > 1) this.print(n.child(1), depth + 1);
      return null;
    }
    const accessor = ACCESSORS[k];
    if (accessor !== undefined) return this.printAbstractStorage(n.first, depth, asPrefix, accessor);
    switch (k) {
      case 'Global':
        this.printChildren(n, depth);
        return null;
      case 'Static':
        this.out += 'static ';
        this.print(n.child(0), depth + 1);
        return null;
      case 'Suffix':
        if (this.o.displayUnmangledSuffix) this.out += ` with unmangled suffix ${JSON.stringify(n.text)}`;
        return null;
      case 'Initializer':
        return this.printEntity(n, depth, asPrefix, 'none', false, 'variable initialization expression');
      case 'PropertyWrapperBackingInitializer':
        return this.printEntity(n, depth, asPrefix, 'none', false, 'property wrapper backing initializer');
      case 'PropertyWrapperInitFromProjectedValue':
        return this.printEntity(n, depth, asPrefix, 'none', false, 'property wrapper init from projected value');
      case 'PropertyWrappedFieldInitAccessor':
        return this.printEntity(n, depth, asPrefix, 'none', false, 'property wrapped field init accessor');
      case 'DefaultArgumentInitializer':
        return this.printEntity(n, depth, asPrefix, 'none', false, 'default argument ', n.child(1).index!);
      case 'DeclContext':
      case 'Type':
        this.print(n.child(0), depth + 1);
        return null;
      case 'TypeMangling':
        if (n.child(0).kind === 'LabelList') this.printFunctionType(n.child(0), n.child(1).first, depth);
        else this.print(n.child(0), depth + 1);
        return null;
      case 'Class':
      case 'Structure':
      case 'Enum':
      case 'Protocol':
      case 'TypeAlias':
      case 'OtherNominalType':
        return this.printEntity(n, depth, asPrefix, 'none', true);
      case 'LocalDeclName':
        this.print(n.child(1), depth + 1);
        this.out += ` #${n.child(0).index! + 1}`;
        return null;
      case 'PrivateDeclName':
        if (n.count > 1) {
          if (this.o.showPrivateDiscriminators) this.out += '(';
          this.print(n.child(1), depth + 1);
          if (this.o.showPrivateDiscriminators) this.out += ` in ${n.child(0).text})`;
        } else if (this.o.showPrivateDiscriminators) this.out += `(in ${n.child(0).text})`;
        return null;
      case 'RelatedEntityDeclName':
        this.out += `related decl '${n.first.text}' for `;
        this.print(n.child(1), depth + 1);
        return null;
      case 'Module':
        if (this.o.displayModuleNames) this.out += n.text;
        return null;
      case 'Identifier':
        this.out += n.text;
        return null;
      case 'Index':
        this.out += n.text ?? String(n.index);
        return null;
      case 'Number':
        this.out += String(n.index);
        return null;
      case 'UnknownIndex':
        this.out += 'unknown index';
        return null;
      case 'FunctionType':
      case 'UncurriedFunctionType':
      case 'NoEscapeFunctionType':
      case 'AutoClosureType':
      case 'EscapingAutoClosureType':
      case 'ThinFunctionType':
      case 'CFunctionPointer':
      case 'ObjCBlock':
      case 'EscapingObjCBlock':
        this.printFunctionType(null, n, depth);
        return null;
      case 'ClangType':
        this.out += n.text;
        return null;
      case 'ArgumentTuple':
        this.printFunctionParameters(null, n, depth, this.o.showFunctionArgumentTypes);
        return null;
      case 'Tuple':
        this.out += '(';
        this.printChildren(n, depth, ', ');
        this.out += ')';
        return null;
      case 'TupleElement': {
        const label = n.children.find((c) => c.kind === 'TupleElementName');
        if (label) this.out += `${label.text}: `;
        const t = n.children.find((c) => c.kind === 'Type');
        if (!t) throw new Bad();
        this.print(t, depth + 1);
        if (n.children.some((c) => c.kind === 'VariadicMarker')) this.out += '...';
        return null;
      }
      case 'TupleElementName':
        this.out += `${n.text}: `;
        return null;
      case 'ReturnType':
        if (n.count === 0) this.out += ` -> ${n.text}`;
        else this.printChildren(n, depth);
        return null;
      case 'Function':
      case 'BoundGenericFunction':
        return this.printEntity(n, depth, asPrefix, 'function', true);
      case 'Subscript':
        return this.printEntity(n, depth, asPrefix, 'function', false, '', -1, 'subscript');
      case 'Variable':
        return this.printEntity(n, depth, asPrefix, 'colon', true);
      case 'ExplicitClosure':
      case 'ImplicitClosure':
        return this.printEntity(n, depth, asPrefix, this.o.showFunctionArgumentTypes ? 'function' : 'none', false,
          k === 'ExplicitClosure' ? 'closure #' : 'implicit closure #', n.child(1).index! + 1);
      case 'Allocator':
        return this.printEntity(n, depth, asPrefix, 'function', false, n.child(0).kind === 'Class' ? '__allocating_init' : 'init');
      case 'Constructor':
        return this.printEntity(n, depth, asPrefix, 'function', n.count > 2, 'init');
      case 'Destructor':
        return this.printEntity(n, depth, asPrefix, 'none', false, 'deinit');
      case 'Deallocator':
        return this.printEntity(n, depth, asPrefix, 'none', false, n.child(0).kind === 'Class' ? '__deallocating_deinit' : 'deinit');
      case 'IsolatedDeallocator':
        return this.printEntity(n, depth, asPrefix, 'none', false, n.child(0).kind === 'Class' ? '__isolated_deallocating_deinit' : 'deinit');
      case 'IVarInitializer':
        return this.printEntity(n, depth, asPrefix, 'none', false, '__ivar_initializer');
      case 'IVarDestroyer':
        return this.printEntity(n, depth, asPrefix, 'none', false, '__ivar_destroyer');
      case 'Extension':
        if (this.o.displayExtensionContexts) {
          this.out += '(extension in ';
          this.print(n.child(0), depth + 1, true);
          this.out += '):';
        }
        this.print(n.child(1), depth + 1);
        if (n.count === 3) this.print(n.child(2), depth + 1);
        return null;
      case 'AnonymousContext':
        if (this.o.displayExtensionContexts) {
          this.print(n.child(1), depth + 1);
          this.out += `.(unknown context at ${n.child(0).text})`;
          if (n.count >= 3 && n.child(2).count > 0) {
            this.out += '<';
            this.print(n.child(2), depth + 1);
            this.out += '>';
          }
        }
        return null;
      case 'InfixOperator':
        this.out += `${n.text} infix`;
        return null;
      case 'PrefixOperator':
        this.out += `${n.text} prefix`;
        return null;
      case 'PostfixOperator':
        this.out += `${n.text} postfix`;
        return null;
      case 'BuiltinTypeName':
        this.out += n.text;
        return null;
      case 'BuiltinTupleType':
        this.out += 'Builtin.TheTupleType';
        return null;
      case 'ObjCAttribute':
        this.out += '@objc ';
        return null;
      case 'NonObjCAttribute':
        this.out += '@nonobjc ';
        return null;
      case 'DynamicAttribute':
        this.out += 'dynamic ';
        return null;
      case 'VTableAttribute':
        this.out += 'override ';
        return null;
      case 'DirectMethodReferenceAttribute':
        this.out += 'super ';
        return null;
      case 'MergedFunction':
        if (!this.o.shortenThunk) this.out += 'merged ';
        return null;
      case 'DistributedThunk':
        if (!this.o.shortenThunk) this.out += 'distributed thunk ';
        return null;
      case 'DistributedAccessor':
        if (!this.o.shortenThunk) this.out += 'distributed accessor for ';
        return null;
      case 'DynamicallyReplaceableFunctionImpl':
        if (!this.o.shortenThunk) this.out += 'dynamically replaceable thunk for ';
        return null;
      case 'DynamicallyReplaceableFunctionKey':
        if (!this.o.shortenThunk) this.out += 'dynamically replaceable key for ';
        return null;
      case 'DynamicallyReplaceableFunctionVar':
        if (!this.o.shortenThunk) this.out += 'dynamically replaceable variable for ';
        return null;
      case 'BackDeploymentThunk':
        if (!this.o.shortenThunk) this.out += 'back deployment thunk for ';
        return null;
      case 'BackDeploymentFallback':
        this.out += 'back deployment fallback for ';
        return null;
      case 'AccessibleFunctionRecord':
        if (!this.o.shortenThunk) this.out += 'accessible function runtime record for ';
        return null;
      case 'HasSymbolQuery':
        this.out += '#_hasSymbol query for ';
        return null;
      case 'AsyncFunctionPointer':
        this.out += 'async function pointer to ';
        return null;
      case 'AsyncAwaitResumePartialFunction':
      case 'AsyncSuspendResumePartialFunction':
        if (this.o.showAsyncResumePartial) {
          this.out += '(';
          this.print(n.child(0), depth + 1);
          this.out += k === 'AsyncAwaitResumePartialFunction' ? ') await resume partial function for ' : ') suspend resume partial function for ';
        }
        return null;
      case 'OutlinedVariable':
        this.out += `outlined variable #${n.index} of `;
        return null;
      case 'OutlinedReadOnlyObject':
        this.out += `outlined read-only object #${n.index} of `;
        return null;
      case 'OutlinedBridgedMethod':
        this.out += `outlined bridged method (${n.text}) of `;
        return null;
      case 'PartialApplyForwarder':
      case 'PartialApplyObjCForwarder':
        this.out += this.o.shortenPartialApply ? 'partial apply' : k === 'PartialApplyForwarder' ? 'partial apply forwarder' : 'partial apply ObjC forwarder';
        if (n.count) {
          this.out += ' for ';
          this.printChildren(n, depth);
        }
        return null;
      case 'KeyPathGetterThunkHelper':
      case 'KeyPathSetterThunkHelper':
        this.out += k === 'KeyPathGetterThunkHelper' ? 'key path getter for ' : 'key path setter for ';
        this.print(n.child(0), depth + 1);
        this.out += ' : ';
        for (let i = 1; i < n.count; i++) if (n.child(i).kind !== 'IsSerialized') this.print(n.child(i), depth + 1);
        if (n.children.some((c) => c.kind === 'IsSerialized')) this.out += ', serialized';
        return null;
      case 'KeyPathEqualsThunkHelper':
      case 'KeyPathHashThunkHelper': {
        this.out += k === 'KeyPathEqualsThunkHelper' ? 'key path index equality operator for ' : 'key path index hash operator for ';
        let last = n.count - 1;
        if (n.child(last).kind === 'IsSerialized') last--;
        if (n.child(last).kind === 'DependentGenericSignature') {
          this.print(n.child(last), depth + 1);
          last--;
        }
        this.out += '(';
        for (let i = 0; i <= last; i++) {
          if (i) this.out += ', ';
          this.print(n.child(i), depth + 1);
        }
        this.out += ')';
        return null;
      }
      case 'IsSerialized':
        this.out += 'serialized';
        return null;
      case 'MetatypeParamsRemoved':
        this.out += 'metatypes-removed';
        return null;
      case 'AsyncRemoved':
        this.out += 'async demoted';
        return null;
      case 'ProtocolWitness':
        this.out += 'protocol witness for ';
        this.print(n.child(1), depth + 1);
        this.out += ' in conformance ';
        this.print(n.child(0), depth + 1);
        return null;
      case 'VTableThunk':
        this.out += 'vtable thunk for ';
        this.print(n.child(1), depth + 1);
        this.out += ' dispatching to ';
        this.print(n.child(0), depth + 1);
        return null;
      case 'LazyProtocolWitnessTableAccessor':
      case 'LazyProtocolWitnessTableCacheVariable':
        this.out += k === 'LazyProtocolWitnessTableAccessor' ? 'lazy protocol witness table accessor for type ' : 'lazy protocol witness table cache variable for type ';
        this.print(n.child(0), depth + 1);
        this.out += ' and conformance ';
        this.print(n.child(1), depth + 1);
        return null;
      case 'AssociatedTypeMetadataAccessor':
        this.out += 'associated type metadata accessor for ';
        this.print(n.child(1), depth + 1);
        this.out += ' in ';
        this.print(n.child(0), depth + 1);
        return null;
      case 'AssociatedTypeWitnessTableAccessor':
        this.out += 'associated type witness table accessor for ';
        this.print(n.child(1), depth + 1);
        this.out += ' : ';
        this.print(n.child(2), depth + 1);
        this.out += ' in ';
        this.print(n.child(0), depth + 1);
        return null;
      case 'BaseWitnessTableAccessor':
        this.out += 'base witness table accessor for ';
        this.print(n.child(1), depth + 1);
        this.out += ' in ';
        this.print(n.child(0), depth + 1);
        return null;
      case 'AssociatedConformanceDescriptor':
      case 'DefaultAssociatedConformanceAccessor':
        this.out += k === 'AssociatedConformanceDescriptor' ? 'associated conformance descriptor for ' : 'default associated conformance accessor for ';
        this.print(n.child(0), depth + 1);
        this.out += '.';
        this.print(n.child(1), depth + 1);
        this.out += ': ';
        this.print(n.child(2), depth + 1);
        return null;
      case 'BaseConformanceDescriptor':
        this.out += 'base conformance descriptor for ';
        this.print(n.child(0), depth + 1);
        this.out += ': ';
        this.print(n.child(1), depth + 1);
        return null;
      case 'AssociatedTypeGenericParamRef':
        this.out += 'generic parameter reference for associated type ';
        this.printChildren(n, depth);
        return null;
      case 'AnonymousDescriptor':
        this.out += 'anonymous descriptor ';
        this.print(n.child(0), depth + 1);
        return null;
      case 'AssocTypePath':
        this.printChildren(n, depth, '.');
        return null;
      case 'ReabstractionThunk':
      case 'ReabstractionThunkHelper': {
        if (this.o.shortenThunk) {
          this.out += 'thunk for ';
          this.print(n.child(n.count - 1), depth + 1);
          return null;
        }
        this.out += 'reabstraction thunk ';
        if (k === 'ReabstractionThunkHelper') this.out += 'helper ';
        let i = 0;
        if (n.count === 3) {
          this.print(n.child(0), depth + 1);
          this.out += ' ';
          i = 1;
        }
        this.out += 'from ';
        this.print(n.child(i + 1), depth + 1);
        this.out += ' to ';
        this.print(n.child(i), depth + 1);
        return null;
      }
      case 'ReabstractionThunkHelperWithSelf': {
        this.out += 'reabstraction thunk ';
        let i = 0;
        if (n.count === 4) {
          this.print(n.child(0), depth + 1);
          this.out += ' ';
          i = 1;
        }
        this.out += 'from ';
        this.print(n.child(i + 2), depth + 1);
        this.out += ' to ';
        this.print(n.child(i + 1), depth + 1);
        this.out += ' self ';
        this.print(n.child(i), depth + 1);
        return null;
      }
      case 'ReabstractionThunkHelperWithGlobalActor':
        this.print(n.child(0), depth + 1);
        this.out += ' with global actor constraint ';
        this.print(n.child(1), depth + 1);
        return null;
      case 'ObjCAsyncCompletionHandlerImpl':
      case 'PredefinedObjCAsyncCompletionHandlerImpl':
        if (k === 'PredefinedObjCAsyncCompletionHandlerImpl') this.out += 'checked ';
        this.out += '@objc completion handler block implementation for ';
        if (n.count >= 4) this.print(n.child(3), depth + 1);
        this.print(n.child(0), depth + 1);
        this.out += ' with result type ';
        this.print(n.child(1), depth + 1);
        switch (n.child(2).index) {
          case 0: break;
          case 1: this.out += ' nonzero on error'; break;
          case 2: this.out += ' zero on error'; break;
          default: this.out += ' <invalid error flag>'; break;
        }
        return null;
      case 'GlobalVariableOnceToken':
      case 'GlobalVariableOnceFunction':
        this.out += k === 'GlobalVariableOnceToken' ? 'one-time initialization token for ' : 'one-time initialization function for ';
        this.print(n.child(1), depth + 1);
        return null;
      case 'GlobalVariableOnceDeclList':
        if (n.count === 1) this.print(n.child(0), depth + 1);
        else {
          this.out += '(';
          this.printChildren(n, depth, ', ');
          this.out += ')';
        }
        return null;
      case 'FieldOffset':
        this.print(n.child(0), depth + 1);
        this.out += 'field offset for ';
        this.print(n.child(1), depth + 1);
        return null;
      case 'Directness':
        this.out += n.index === 0 ? 'direct ' : 'indirect ';
        return null;
      case 'ValueWitness':
        this.out += n.child(0).text;
        this.out += this.o.shortenValueWitness ? ' for ' : ' value witness for ';
        this.print(n.child(1), depth + 1);
        return null;
      case 'FunctionSignatureSpecialization':
        this.printSpecializationPrefix(n, 'function signature specialization', depth);
        return null;
      case 'GenericPartialSpecialization':
        this.printSpecializationPrefix(n, 'partial generic specialization', depth);
        return null;
      case 'GenericPartialSpecializationNotReAbstracted':
        this.printSpecializationPrefix(n, 'partial generic specialization <not re-abstracted>', depth);
        return null;
      case 'GenericSpecialization':
      case 'GenericSpecializationInResilienceDomain':
        this.printSpecializationPrefix(n, 'generic specialization', depth);
        return null;
      case 'GenericSpecializationPrespecialized':
        this.printSpecializationPrefix(n, 'generic pre-specialization', depth);
        return null;
      case 'GenericSpecializationNotReAbstracted':
        this.printSpecializationPrefix(n, 'generic not re-abstracted specialization', depth);
        return null;
      case 'InlinedGenericFunction':
        this.printSpecializationPrefix(n, 'inlined generic function', depth);
        return null;
      case 'GenericSpecializationParam':
        this.print(n.child(0), depth + 1);
        for (let i = 1; i < n.count; i++) {
          this.out += i === 1 ? ' with ' : ' and ';
          this.print(n.child(i), depth + 1);
        }
        return null;
      case 'FunctionSignatureSpecializationParam':
      case 'FunctionSignatureSpecializationReturn':
        this.printFunctionSigSpecializationParams(n, depth);
        return null;
      case 'FunctionSignatureSpecializationParamPayload':
        this.out += n.text;
        return null;
      case 'FunctionSignatureSpecializationParamKind':
        this.printFssKind(n.index!);
        return null;
      case 'SpecializationPassID':
        this.out += String(n.index);
        return null;
      case 'ProtocolConformance':
        if (n.count === 4) {
          this.out += 'property behavior storage of ';
          this.print(n.child(2), depth + 1);
          this.out += ' in ';
          this.print(n.child(0), depth + 1);
          this.out += ' : ';
          this.print(n.child(1), depth + 1);
        } else {
          this.print(n.child(0), depth + 1);
          if (this.o.displayProtocolConformances) {
            this.out += ' : ';
            this.print(n.child(1), depth + 1);
            this.out += ' in ';
            this.print(n.child(2), depth + 1);
          }
        }
        return null;
      case 'TypeList':
        this.printChildren(n, depth);
        return null;
      case 'LabelList':
        return null;
      case 'BoundGenericClass':
      case 'BoundGenericStructure':
      case 'BoundGenericEnum':
      case 'BoundGenericProtocol':
      case 'BoundGenericOtherNominalType':
      case 'BoundGenericTypeAlias':
        this.printBoundGeneric(n, depth);
        return null;
      case 'DynamicSelf':
        this.out += 'Self';
        return null;
      case 'ErrorType':
        this.out += '<ERROR TYPE>';
        return null;
      case 'Metatype': {
        let i = 0;
        if (n.count === 2) {
          this.print(n.child(0), depth + 1);
          this.out += ' ';
          i = 1;
        }
        const t = n.child(i).child(0);
        this.printWithParens(t, depth);
        this.out += isExistential(t) ? '.Protocol' : '.Type';
        return null;
      }
      case 'ExistentialMetatype': {
        let i = 0;
        if (n.count === 2) {
          this.print(n.child(0), depth + 1);
          this.out += ' ';
          i = 1;
        }
        this.print(n.child(i), depth + 1);
        this.out += '.Type';
        return null;
      }
      case 'MetatypeRepresentation':
        this.out += n.text;
        return null;
      case 'ProtocolList': {
        const list = n.child(0);
        if (list.count === 0) this.out += 'Any';
        else this.printChildren(list, depth, ' & ');
        return null;
      }
      case 'ProtocolListWithClass': {
        this.print(n.child(1), depth + 1);
        this.out += ' & ';
        this.printChildren(n.child(0).child(0), depth, ' & ');
        return null;
      }
      case 'ProtocolListWithAnyObject': {
        const list = n.child(0).child(0);
        if (list.count > 0) {
          this.printChildren(list, depth, ' & ');
          this.out += ' & ';
        }
        this.out += 'Swift.AnyObject';
        return null;
      }
      case 'AssociatedTypeRef':
        this.print(n.child(0), depth + 1);
        this.out += `.${n.child(1).text}`;
        return null;
      case 'DependentMemberType':
        this.print(n.child(0), depth + 1);
        this.out += '.';
        this.print(n.child(1), depth + 1);
        return null;
      case 'DependentAssociatedTypeRef':
        if (n.count > 1) {
          this.print(n.child(1), depth + 1);
          this.out += '.';
        }
        this.print(n.child(0), depth + 1);
        return null;
      case 'DependentGenericParamType':
        this.out += genericParameterName(n.child(0).index!, n.child(1).index!);
        return null;
      case 'DependentGenericType': {
        this.print(n.child(0), depth + 1);
        const t = n.child(1);
        if (this.needSpaceBeforeType(t)) this.out += ' ';
        this.print(t, depth + 1);
        return null;
      }
      case 'DependentGenericSignature':
      case 'DependentPseudogenericSignature':
        this.printGenericSignature(n, depth);
        return null;
      case 'DependentGenericConformanceRequirement':
        this.print(n.child(0), depth + 1);
        this.out += ': ';
        this.print(n.child(1), depth + 1);
        return null;
      case 'DependentGenericInverseConformanceRequirement': {
        this.print(n.child(0), depth + 1);
        this.out += ': ~';
        const i = n.child(1).index!;
        this.out += i === 0 ? 'Swift.Copyable' : i === 1 ? 'Swift.Escapable' : `Swift.<bit ${i}>`;
        return null;
      }
      case 'DependentGenericLayoutRequirement': {
        this.print(n.child(0), depth + 1);
        this.out += ': ';
        const c = n.child(1).text!;
        const names: Record<string, string> = {
          U: '_UnknownLayout', R: '_RefCountedObject', N: '_NativeRefCountedObject', C: 'AnyObject', D: '_NativeClass', T: '_Trivial',
          E: '_Trivial', e: '_Trivial', M: '_TrivialAtMost', m: '_TrivialAtMost', S: '_TrivialStride', B: '_BridgeObject',
        };
        this.out += names[c] ?? '';
        if (n.count > 2) {
          this.out += '(';
          this.print(n.child(2), depth + 1);
          if (n.count > 3) {
            this.out += ', ';
            this.print(n.child(3), depth + 1);
          }
          this.out += ')';
        }
        return null;
      }
      case 'DependentGenericSameTypeRequirement':
        this.print(n.child(0), depth + 1);
        this.out += ' == ';
        this.print(n.child(1), depth + 1);
        return null;
      case 'DependentGenericSameShapeRequirement':
        this.print(n.child(0), depth + 1);
        this.out += '.shape == ';
        this.print(n.child(1), depth + 1);
        this.out += '.shape';
        return null;
      case 'DependentGenericParamPackMarker':
      case 'DependentGenericParamValueMarker':
        return null;
      case 'ThrowsAnnotation':
        this.out += ' throws';
        return null;
      case 'TypedThrowsAnnotation':
        this.out += ' throws(';
        if (n.count === 1) this.print(n.child(0), depth + 1);
        this.out += ')';
        return null;
      case 'AsyncAnnotation':
        this.out += ' async';
        return null;
      case 'ConcurrentFunctionType':
        this.out += '@Sendable ';
        return null;
      case 'IsolatedAnyFunctionType':
        this.out += '@isolated(any) ';
        return null;
      case 'NonIsolatedCallerFunctionType':
        this.out += 'nonisolated(nonsending) ';
        return null;
      case 'SendingResultFunctionType':
        this.out += 'sending ';
        return null;
      case 'GlobalActorFunctionType':
        if (n.count > 0) {
          this.out += '@';
          this.print(n.child(0), depth + 1);
          this.out += ' ';
        }
        return null;
      case 'OpaqueReturnType':
        this.out += 'some';
        return null;
      case 'Pack':
        this.out += 'Pack{';
        this.printChildren(n, depth, ', ');
        this.out += '}';
        return null;
      case 'PackExpansion':
        this.out += 'repeat ';
        this.print(n.child(0), depth + 1);
        return null;
      case 'OpaqueReturnTypeOf':
        this.out += '<<opaque return type of ';
        this.printChildren(n, depth);
        this.out += '>>';
        return null;
      case 'OpaqueType':
        this.print(n.child(0), depth + 1);
        this.out += '.';
        this.print(n.child(1), depth + 1);
        return null;
      case 'ConstrainedExistential':
        this.out += 'any ';
        this.print(n.child(0), depth + 1);
        this.out += '<';
        this.print(n.child(1), depth + 1);
        this.out += '>';
        return null;
      case 'ConstrainedExistentialRequirementList':
        this.printChildren(n, depth, ', ');
        return null;
      case 'ConstrainedExistentialSelf':
        this.out += 'Self';
        return null;
      case 'SugaredOptional':
        this.printWithParens(n.child(0), depth);
        this.out += '?';
        return null;
      case 'SugaredArray':
        this.out += '[';
        this.print(n.child(0), depth + 1);
        this.out += ']';
        return null;
      case 'SugaredDictionary':
        this.out += '[';
        this.print(n.child(0), depth + 1);
        this.out += ' : ';
        this.print(n.child(1), depth + 1);
        this.out += ']';
        return null;
      case 'SugaredParen':
        this.out += '(';
        this.print(n.child(0), depth + 1);
        this.out += ')';
        return null;
      case 'SILBoxTypeWithLayout': {
        const layout = n.child(0);
        let args: N = null;
        if (n.count === 3) {
          this.print(n.child(1), depth + 1);
          this.out += ' ';
          args = n.child(2);
        }
        this.print(layout, depth + 1);
        if (args) {
          this.out += ' <';
          this.printChildren(args, depth, ', ');
          this.out += '>';
        }
        return null;
      }
      case 'SILBoxLayout':
        this.out += '{';
        n.children.forEach((c, i) => {
          if (i) this.out += ',';
          this.out += ' ';
          this.print(c, depth + 1);
        });
        this.out += ' }';
        return null;
      case 'SILBoxImmutableField':
      case 'SILBoxMutableField':
        this.out += k === 'SILBoxImmutableField' ? 'let ' : 'var ';
        this.print(n.child(0), depth + 1);
        return null;
      case 'ImplFunctionType':
        this.printImplFunctionType(n, depth);
        return null;
      case 'ImplYield':
      case 'ImplParameter':
      case 'ImplResult':
        if (k === 'ImplYield') this.out += '@yields ';
        n.children.forEach((c, i) => {
          this.print(c, depth + 1);
          if (i < n.count - 1) this.out += ' ';
        });
        return null;
      case 'ImplErrorResult':
        this.out += '@error ';
        n.children.forEach((c, i) => {
          this.print(c, depth + 1);
          if (i < n.count - 1) this.out += ' ';
        });
        return null;
      case 'ImplConvention':
      case 'ImplFunctionAttribute':
      case 'ImplCoroutineKind':
      case 'ImplParameterResultDifferentiability':
      case 'ImplParameterSending':
      case 'ImplParameterIsolated':
      case 'ImplParameterImplicitLeading':
        this.out += n.text;
        return null;
      case 'ImplEscaping':
        this.out += '@escaping';
        return null;
      case 'ImplErasedIsolation':
        this.out += '@isolated(any)';
        return null;
      case 'ImplSendingResult':
        this.out += 'sending';
        return null;
      case 'ImplFunctionConvention':
        this.out += '@convention(';
        this.print(n.child(0), depth + 1);
        if (n.count > 1) {
          this.out += ', mangledCType: "';
          this.print(n.child(1), depth + 1);
          this.out += '"';
        }
        this.out += ')';
        return null;
      case 'ImplFunctionConventionName':
        this.out += n.text;
        return null;
      case 'ImplDifferentiabilityKind': {
        const names: Record<string, string> = { d: '@differentiable', l: '@differentiable(_linear)', f: '@differentiable(_forward)', r: '@differentiable(reverse)' };
        this.out += names[n.text!] ?? '';
        return null;
      }
      case 'AccessorAttachedMacroExpansion':
      case 'MemberAttributeAttachedMacroExpansion':
      case 'MemberAttachedMacroExpansion':
      case 'PeerAttachedMacroExpansion':
      case 'ConformanceAttachedMacroExpansion':
      case 'ExtensionAttachedMacroExpansion':
      case 'BodyAttachedMacroExpansion':
      case 'PreambleAttachedMacroExpansion': {
        const words: Record<string, string> = {
          AccessorAttachedMacroExpansion: 'accessor', MemberAttributeAttachedMacroExpansion: 'member attribute',
          MemberAttachedMacroExpansion: 'member', PeerAttachedMacroExpansion: 'peer', ConformanceAttachedMacroExpansion: 'conformance',
          ExtensionAttachedMacroExpansion: 'extension', BodyAttachedMacroExpansion: 'body', PreambleAttachedMacroExpansion: 'preamble',
        };
        const name = new Printer(this.o);
        name.print(n.child(2), 0);
        return this.printEntity(n, depth, asPrefix, 'none', true, `${words[k]} macro @${name.out} expansion #`, n.child(3).index! + 1);
      }
      case 'FreestandingMacroExpansion':
        return this.printEntity(n, depth, asPrefix, 'none', true, 'freestanding macro expansion #', n.child(2).index! + 1);
      case 'MacroExpansionUniqueName':
        return this.printEntity(n, depth, asPrefix, 'none', true, 'unique name #', n.child(2).index! + 1);
      default:
        throw new Bad();
    }
  }

  private printAbstractStorage(n: SwiftNode, depth: number, asPrefix: boolean, extra: string): N {
    if (n.kind === 'Variable') return this.printEntity(n, depth, asPrefix, 'colon', true, extra);
    if (n.kind === 'Subscript') return this.printEntity(n, depth, asPrefix, 'colon', false, extra, -1, 'subscript');
    throw new Bad();
  }

  private printEntity(entity: SwiftNode, depth: number, asPrefix: boolean, typePr: TypePrinting, hasName: boolean,
    extraName = '', extraIndex = -1, overwriteName = ''): N {
    let genericFunctionTypeList: N = null;
    if (entity.kind === 'BoundGenericFunction') {
      genericFunctionTypeList = entity.child(1);
      entity = entity.first;
    }
    let multiWordName = extraName.includes(' ');
    const localName = hasName && entity.child(1).kind === 'LocalDeclName';
    if (localName) multiWordName = true;
    if (asPrefix && (typePr !== 'none' || multiWordName)) return entity;

    // The context is printed before the name (`Counter.increment`), or after it when the name
    // has words of its own (`closure #1 in Counter.increment`); modules count as contexts too.
    let postfixContext: N = null;
    const ctx = entity.child(0);
    if (multiWordName) postfixContext = ctx;
    else {
      const at = this.out.length;
      postfixContext = this.print(ctx, depth + 1, true);
      if (this.out.length !== at) this.out += '.';
    }
    if (hasName || overwriteName) {
      if (extraName && multiWordName) {
        this.out += extraName;
        if (extraIndex >= 0) this.out += String(extraIndex);
        this.out += ' of ';
        extraName = '';
        extraIndex = -1;
      }
      const at = this.out.length;
      if (overwriteName) this.out += overwriteName;
      else {
        const name = entity.child(1);
        if (name.kind !== 'PrivateDeclName') this.print(name, depth + 1);
        const privateName = entity.children.find((c) => c.kind === 'PrivateDeclName');
        if (privateName) this.print(privateName, depth + 1);
      }
      if (this.out.length !== at && extraName) this.out += '.';
    }
    if (extraName) {
      this.out += extraName;
      if (extraIndex >= 0) this.out += String(extraIndex);
    }
    if (typePr !== 'none') {
      const typeNode = entity.children.find((c) => c.kind === 'Type');
      if (!typeNode) throw new Bad();
      const t = typeNode.child(0);
      if (typePr === 'function') {
        let f = t;
        while (f.kind === 'DependentGenericType') f = f.child(1).child(0);
        if (!['FunctionType', 'NoEscapeFunctionType', 'UncurriedFunctionType', 'CFunctionPointer', 'ThinFunctionType'].includes(f.kind)) typePr = 'colon';
      }
      if (typePr === 'colon') {
        if (this.o.displayEntityTypes) {
          this.out += ' : ';
          this.printEntityType(entity, t, genericFunctionTypeList, depth);
        }
      } else {
        if (multiWordName || this.needSpaceBeforeType(t)) this.out += ' ';
        this.printEntityType(entity, t, genericFunctionTypeList, depth);
      }
    }
    if (!asPrefix && postfixContext) {
      this.out += ['DefaultArgumentInitializer', 'Initializer', 'PropertyWrapperBackingInitializer', 'PropertyWrapperInitFromProjectedValue', 'PropertyWrappedFieldInitAccessor'].includes(entity.kind) ? ' of ' : ' in ';
      this.print(postfixContext, depth + 1);
      postfixContext = null;
    }
    return postfixContext;
  }

  private printEntityType(entity: SwiftNode, t: SwiftNode, genericFunctionTypeList: N, depth: number): void {
    const labels = entity.children.find((c) => c.kind === 'LabelList') ?? null;
    if (labels || genericFunctionTypeList) {
      if (genericFunctionTypeList) {
        this.out += '<';
        this.printChildren(genericFunctionTypeList, depth, ', ');
        this.out += '>';
      }
      if (t.kind === 'DependentGenericType') {
        if (!genericFunctionTypeList) this.print(t.child(0), depth + 1);
        const dependent = t.child(1);
        if (this.needSpaceBeforeType(dependent)) this.out += ' ';
        t = dependent.first;
      }
      this.printFunctionType(labels, t, depth);
    } else this.print(t, depth + 1);
  }

  private printFunctionType(labels: N, n: SwiftNode, depth: number): void {
    if (n.count < 2) throw new Bad();
    const convention = (name: string) => {
      this.out += `@convention(${name}`;
      if (n.first.kind === 'ClangType') {
        this.out += ', mangledCType: "';
        this.print(n.first, depth + 1);
        this.out += '"';
      }
      this.out += ') ';
    };
    switch (n.kind) {
      case 'FunctionType':
      case 'UncurriedFunctionType':
      case 'NoEscapeFunctionType':
        break;
      case 'AutoClosureType':
      case 'EscapingAutoClosureType':
        this.out += '@autoclosure ';
        break;
      case 'ThinFunctionType':
        this.out += '@convention(thin) ';
        break;
      case 'CFunctionPointer':
        convention('c');
        break;
      case 'EscapingObjCBlock':
        this.out += '@escaping ';
        convention('block');
        break;
      case 'ObjCBlock':
        convention('block');
        break;
      default:
        throw new Bad();
    }
    const has = (kind: string) => n.children.find((c) => c.kind === kind);
    const isolation = n.children.find((c) => c.kind === 'IsolatedAnyFunctionType' || c.kind === 'GlobalActorFunctionType' || c.kind === 'NonIsolatedCallerFunctionType');
    if (isolation) this.print(isolation, depth + 1);
    const diff = has('DifferentiableFunctionType');
    if (diff) {
      const names: Record<string, string> = { f: '@differentiable(_forward) ', r: '@differentiable(reverse) ', l: '@differentiable(_linear) ', d: '@differentiable ' };
      this.out += names[String.fromCharCode(diff.index!)] ?? '';
    }
    const thrown = n.children.find((c) => c.kind === 'ThrowsAnnotation' || c.kind === 'TypedThrowsAnnotation');
    if (has('ConcurrentFunctionType')) this.out += '@Sendable ';
    const args = n.child(n.count - 2);
    this.printFunctionParameters(labels, args, depth, this.o.showFunctionArgumentTypes);
    if (!this.o.showFunctionArgumentTypes) return;
    if (has('AsyncAnnotation')) this.out += ' async';
    if (thrown) this.print(thrown, depth + 1);
    this.out += ' -> ';
    if (has('SendingResultFunctionType')) this.out += 'sending ';
    this.print(n.child(n.count - 1), depth + 1);
  }

  private printFunctionParameters(labels: N, args: SwiftNode, depth: number, showTypes: boolean): void {
    if (args.kind !== 'ArgumentTuple') throw new Bad();
    const params = args.first.first;
    if (params.kind !== 'Tuple') {
      if (showTypes) {
        this.out += '(';
        this.print(params, depth + 1);
        this.out += ')';
      } else this.out += '(_:)';
      return;
    }
    const hasLabels = !!labels && labels.count > 0;
    this.out += '(';
    params.children.forEach((param, i) => {
      if (i && showTypes) this.out += ', ';
      if (hasLabels) {
        const label = labels!.child(i);
        this.out += `${label.kind === 'Identifier' ? label.text : '_'}:`;
      } else if (!showTypes) {
        const label = param.children.find((c) => c.kind === 'TupleElementName');
        this.out += label ? `${label.text}:` : '_:';
      }
      if (hasLabels && showTypes) this.out += ' ';
      if (showTypes) this.print(param, depth + 1);
    });
    this.out += ')';
  }

  private printBoundGeneric(n: SwiftNode, depth: number): void {
    if (n.count < 2) return;
    if (n.count !== 2 || !this.o.synthesizeSugarOnTypes || n.kind === 'BoundGenericClass') return this.printBoundGenericNoSugar(n, depth);
    if (n.kind === 'BoundGenericProtocol') {
      this.printChildren(n.child(1), depth);
      this.out += ' as ';
      this.print(n.child(0), depth + 1);
      return;
    }
    const sugar = findSugar(n);
    const args = n.child(1);
    if (sugar === 'optional' || sugar === 'implicit') {
      this.printWithParens(args.child(0), depth);
      this.out += sugar === 'optional' ? '?' : '!';
    } else if (sugar === 'array') {
      this.out += '[';
      this.print(args.child(0), depth + 1);
      this.out += ']';
    } else if (sugar === 'dictionary') {
      this.out += '[';
      this.print(args.child(0), depth + 1);
      this.out += ' : ';
      this.print(args.child(1), depth + 1);
      this.out += ']';
    } else this.printBoundGenericNoSugar(n, depth);
  }

  private printBoundGenericNoSugar(n: SwiftNode, depth: number): void {
    this.print(n.child(0), depth + 1);
    this.out += '<';
    this.printChildren(n.child(1), depth, ', ');
    this.out += '>';
  }

  private printGenericSignature(n: SwiftNode, depth: number): void {
    this.out += '<';
    let numParams = 0;
    while (numParams < n.count && n.child(numParams).kind === 'DependentGenericParamCount') numParams++;
    let firstRequirement = numParams;
    while (firstRequirement < n.count) {
      let c = n.child(firstRequirement);
      if (c.kind === 'Type') c = c.first;
      if (c.kind !== 'DependentGenericParamPackMarker' && c.kind !== 'DependentGenericParamValueMarker') break;
      firstRequirement++;
    }
    const marker = (kind: string, d: number, i: number): N => {
      for (let r = numParams; r < firstRequirement; r++) {
        const c = n.child(r);
        if (c.kind !== kind) continue;
        let t = c.first;
        if (t.kind !== 'Type') continue;
        t = t.first;
        if (t.kind !== 'DependentGenericParamType') continue;
        // swift-demangle compares the depth with the index and the index with the depth.
        if (t.child(0).index === i && t.child(1).index === d) return c;
      }
      return null;
    };
    for (let d = 0; d < numParams; d++) {
      if (d) this.out += '><';
      const count = n.child(d).index!;
      for (let i = 0; i < count; i++) {
        if (i) this.out += ', ';
        if (i >= 128) {
          this.out += '...';
          break;
        }
        if (marker('DependentGenericParamPackMarker', d, i)) this.out += 'each ';
        const value = marker('DependentGenericParamValueMarker', d, i);
        if (value) this.out += 'let ';
        this.out += genericParameterName(d, i);
        if (value) {
          this.out += ': ';
          this.print(value.child(1), depth + 1);
        }
      }
    }
    if (firstRequirement !== n.count && this.o.displayWhereClauses) {
      this.out += ' where ';
      for (let r = firstRequirement; r < n.count; r++) {
        if (r > firstRequirement) this.out += ', ';
        this.print(n.child(r), depth + 1);
      }
    }
    this.out += '>';
  }

  private printSpecializationPrefix(n: SwiftNode, description: string, depth: number): void {
    if (!this.o.displayGenericSpecializations) {
      if (!this.specializationPrefixPrinted) {
        this.out += 'specialized ';
        this.specializationPrefixPrinted = true;
      }
      return;
    }
    this.out += `${description} <`;
    let separator = '';
    let argNum = 0;
    for (const c of n.children) {
      switch (c.kind) {
        case 'SpecializationPassID':
        case 'DroppedArgument':
          break;
        case 'IsSerialized':
          this.out += separator;
          separator = ', ';
          this.print(c, depth + 1);
          break;
        default:
          if (c.count) {
            this.out += separator;
            separator = ', ';
            if (c.kind === 'FunctionSignatureSpecializationParam') {
              this.out += `Arg[${argNum}] = `;
              this.printFunctionSigSpecializationParams(c, depth);
            } else if (c.kind === 'FunctionSignatureSpecializationReturn') {
              this.out += 'Return = ';
              this.printFunctionSigSpecializationParams(c, depth);
            } else this.print(c, depth + 1);
          }
          argNum++;
          break;
      }
    }
    this.out += '> of ';
  }

  private printFunctionSigSpecializationParams(n: SwiftNode, depth: number): void {
    let i = 0;
    while (i < n.count) {
      const kind = n.child(i).index!;
      switch (kind) {
        case FSS.BoxToValue:
        case FSS.BoxToStack:
        case FSS.InOutToOut:
          this.print(n.child(i++), depth + 1);
          break;
        case FSS.ConstantPropFunction:
        case FSS.ConstantPropGlobal: {
          this.out += '[';
          this.print(n.child(i++), depth + 1);
          this.out += ' : ';
          const text = n.child(i++).text!;
          // Printed as the runtime's demangler prints a name by default: without the sugar.
          const tree = parseSwift(text);
          const inner = new Printer({ ...FULL, synthesizeSugarOnTypes: false });
          if (tree) inner.print(tree, 0);
          this.out += tree ? inner.out : text;
          this.out += ']';
          break;
        }
        case FSS.ConstantPropInteger:
        case FSS.ConstantPropFloat:
          this.out += '[';
          this.print(n.child(i++), depth + 1);
          this.out += ' : ';
          this.print(n.child(i++), depth + 1);
          this.out += ']';
          break;
        case FSS.ConstantPropString:
          this.out += '[';
          this.print(n.child(i++), depth + 1);
          this.out += ' : ';
          this.print(n.child(i++), depth + 1);
          this.out += "'";
          this.print(n.child(i++), depth + 1);
          this.out += "']";
          break;
        case FSS.ConstantPropKeyPath:
          this.out += '[';
          this.print(n.child(i++), depth + 1);
          this.out += ' : ';
          this.print(n.child(i++), depth + 1);
          this.out += '<';
          this.print(n.child(i++), depth + 1);
          this.out += ',';
          this.print(n.child(i++), depth + 1);
          this.out += '>]';
          break;
        case FSS.ClosureProp:
        case FSS.ClosurePropPreviousArg:
        case FSS.ClosurePropEscaping:
          this.out += '[';
          this.print(n.child(i++), depth + 1);
          this.out += ' : ';
          this.print(n.child(i++), depth + 1);
          this.out += ', Argument Types : [';
          while (i < n.count) {
            const c = n.child(i);
            if (c.kind !== 'Type') break;
            this.print(c, depth + 1);
            i++;
            if (i < n.count && n.child(i).text !== undefined) this.out += ', ';
          }
          this.out += ']';
          break;
        default:
          this.print(n.child(i++), depth + 1);
          break;
      }
    }
  }

  private printFssKind(raw: number): void {
    const options: string[] = [];
    if (raw & FSS.ExistentialToGeneric) options.push('Existential To Protocol Constrained Generic');
    if (raw & FSS.Dead) options.push('Dead');
    if (raw & FSS.OwnedToGuaranteed) options.push('Owned To Guaranteed');
    if (raw & FSS.GuaranteedToOwned) options.push('Guaranteed To Owned');
    if (raw & FSS.SROA) options.push('Exploded');
    if (options.length) {
      this.out += options.join(' and ');
      return;
    }
    const names: Record<number, string> = {
      [FSS.BoxToValue]: 'Value Promoted from Box', [FSS.BoxToStack]: 'Stack Promoted from Box', [FSS.InOutToOut]: 'InOut Converted to Out',
      [FSS.ConstantPropFunction]: 'Constant Propagated Function', [FSS.ConstantPropGlobal]: 'Constant Propagated Global',
      [FSS.ConstantPropInteger]: 'Constant Propagated Integer', [FSS.ConstantPropFloat]: 'Constant Propagated Float',
      [FSS.ConstantPropString]: 'Constant Propagated String', [FSS.ConstantPropKeyPath]: 'Constant Propagated KeyPath',
      [FSS.ClosureProp]: 'Closure Propagated', [FSS.ClosurePropPreviousArg]: 'Closure Propagated : Previous Argument',
      [FSS.ClosurePropEscaping]: 'Escaping Closure Propagated',
    };
    const name = names[raw];
    if (name === undefined) throw new Bad();
    this.out += name;
  }

  private printImplFunctionType(fn: SwiftNode, depth: number): void {
    let patternSubs: N = null;
    let invocationSubs: N = null;
    let sendingResult: N = null;
    let state = 0;
    const transition = (to: number) => {
      for (; state < to; state++) {
        if (state === 0) {
          if (patternSubs) {
            this.out += '@substituted ';
            this.print(patternSubs.child(0), depth + 1);
            this.out += ' ';
          }
          this.out += '(';
        } else {
          this.out += ') -> ';
          if (sendingResult) {
            this.print(sendingResult, depth + 1);
            this.out += ' ';
          }
          this.out += '(';
        }
      }
    };
    for (const c of fn.children) {
      if (c.kind === 'ImplParameter') {
        if (state === 1) this.out += ', ';
        transition(1);
        this.print(c, depth + 1);
      } else if (c.kind === 'ImplResult' || c.kind === 'ImplYield' || c.kind === 'ImplErrorResult') {
        if (state === 2) this.out += ', ';
        transition(2);
        this.print(c, depth + 1);
      } else if (c.kind === 'ImplPatternSubstitutions') patternSubs = c;
      else if (c.kind === 'ImplInvocationSubstitutions') invocationSubs = c;
      else if (c.kind === 'ImplSendingResult') sendingResult = c;
      else {
        this.print(c, depth + 1);
        this.out += ' ';
      }
    }
    transition(2);
    this.out += ')';
    // swift-demangle runs the substitutions together, with nothing between them.
    if (patternSubs) {
      this.out += ' for <';
      this.printChildren(patternSubs.child(1), depth);
      this.out += '>';
    }
    if (invocationSubs) {
      this.out += ' for <';
      this.printChildren(invocationSubs.child(0), depth);
      this.out += '>';
    }
  }
}

function isExistential(n: SwiftNode): boolean {
  return ['ExistentialMetatype', 'ProtocolList', 'ProtocolListWithClass', 'ProtocolListWithAnyObject'].includes(n.kind);
}

function findSugar(n: SwiftNode): 'optional' | 'implicit' | 'array' | 'dictionary' | 'none' {
  if (n.count === 1 && n.kind === 'Type') return findSugar(n.first);
  if (n.count !== 2 || (n.kind !== 'BoundGenericEnum' && n.kind !== 'BoundGenericStructure')) return 'none';
  const unbound = n.child(0).first;
  const args = n.child(1);
  if (unbound.count < 2) return 'none';
  const isSwift = unbound.child(0).kind === 'Module' && unbound.child(0).text === 'Swift';
  const name = unbound.child(1).kind === 'Identifier' ? unbound.child(1).text : undefined;
  if (!isSwift) return 'none';
  if (n.kind === 'BoundGenericEnum') {
    if (name === 'Optional' && args.count === 1) return 'optional';
    if (name === 'ImplicitlyUnwrappedOptional' && args.count === 1) return 'implicit';
    return 'none';
  }
  if (name === 'Array' && args.count === 1) return 'array';
  if (name === 'Dictionary' && args.count === 2) return 'dictionary';
  return 'none';
}

/**
 * A Swift symbol demangled, in full and simplified, or null when it is not one
 * or does not parse.
 */
export function demangleSwift(symbol: string): { full: string; short: string } | null {
  const tree = parseSwift(symbol);
  if (!tree) return null;
  try {
    const full = new Printer(FULL);
    full.print(tree, 0);
    const short = new Printer(SIMPLIFIED);
    short.print(tree, 0);
    return { full: full.out, short: short.out };
  } catch (err) {
    if (err instanceof Bad) return null;
    throw err;
  }
}
