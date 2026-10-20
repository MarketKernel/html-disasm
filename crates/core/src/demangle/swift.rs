//! Swift symbol names (`$s…`, Swift 5 and later; `$S…`, Swift 4.2) back to
//! what they declare, printed as Apple's `swift-demangle` prints them: in full
//! (`HelloKit.Counter.increment(by: Swift.Int) -> Swift.Int`) and simplified,
//! as its `--simplified` does (`Counter.increment(by:)`), for the listing.
//!
//! The mangling is a postfix language: each operator pops what it applies to
//! from a stack of nodes and pushes the node it makes, so a symbol becomes a
//! tree, which is then printed. Names already seen are referred to again by
//! substitutions (`A…`), and words already seen inside identifiers by letters.
//! The grammar is the one in the Swift repository's docs/ABI/Mangling.rst; the
//! tree has the shape and the node names of the Swift runtime's own demangler,
//! so that `tools/verify-swift.mjs` can compare the two node by node, and the
//! printer follows the text `swift-demangle` gives for each node.
//!
//! A name that does not parse, or holds a node the printer does not know, is
//! not demangled at all rather than printed wrong.
//!
//! The nodes live in one arena and refer to each other by index. A
//! substitution is the same node seen again, and some nodes gain children
//! after they were linked; with indices both behave as the shared objects of
//! the TypeScript original did.

use super::{push_utf16, Units};

macro_rules! kinds {
    ($($k:ident),* $(,)?) => {
        /// The kind of a node, named as the Swift runtime's demangler names it.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum Kind { $($k),* }
        impl Kind {
            pub fn name(self) -> &'static str {
                match self { $(Kind::$k => stringify!($k)),* }
            }
        }
    };
}

kinds! {
    AccessibleFunctionRecord, AccessorAttachedMacroExpansion, Allocator, AnonymousContext, AnonymousDescriptor,
    AnyProtocolConformanceList, ArgumentTuple, AssocTypePath, AssociatedConformanceDescriptor, AssociatedType,
    AssociatedTypeDescriptor, AssociatedTypeGenericParamRef, AssociatedTypeMetadataAccessor, AssociatedTypeRef,
    AssociatedTypeWitnessTableAccessor, AsyncAnnotation, AsyncAwaitResumePartialFunction, AsyncFunctionPointer, AsyncRemoved,
    AsyncSuspendResumePartialFunction, AutoClosureType, AutoDiffFunction, BackDeploymentFallback, BackDeploymentThunk,
    BaseConformanceDescriptor, BaseWitnessTableAccessor, BodyAttachedMacroExpansion, BoundGenericClass, BoundGenericEnum,
    BoundGenericFunction, BoundGenericOtherNominalType, BoundGenericProtocol, BoundGenericStructure, BoundGenericTypeAlias,
    BuiltinTupleType, BuiltinTypeName, CFunctionPointer, CanonicalPrespecializedGenericTypeCachingOnceToken,
    CanonicalSpecializedGenericMetaclass, CanonicalSpecializedGenericTypeMetadataAccessFunction, ClangType, Class,
    ClassMetadataBaseOffset, CompileTimeLiteral, ConcreteProtocolConformance, ConcurrentFunctionType,
    ConformanceAttachedMacroExpansion, ConstValue, ConstrainedExistential, ConstrainedExistentialRequirementList,
    ConstrainedExistentialSelf, Constructor, CoroFunctionPointer, CoroutineContinuationPrototype, CurryThunk, Deallocator,
    DeclContext, DefaultArgumentInitializer, DefaultAssociatedConformanceAccessor, DefaultAssociatedTypeMetadataAccessor,
    DefaultOverride, DependentAssociatedConformance, DependentAssociatedTypeRef, DependentGenericConformanceRequirement,
    DependentGenericInverseConformanceRequirement, DependentGenericLayoutRequirement, DependentGenericParamCount,
    DependentGenericParamPackMarker, DependentGenericParamType, DependentGenericParamValueMarker,
    DependentGenericSameShapeRequirement, DependentGenericSameTypeRequirement, DependentGenericSignature,
    DependentGenericType, DependentMemberType, DependentProtocolConformanceAssociated, DependentProtocolConformanceInherited,
    DependentProtocolConformanceRoot, DependentPseudogenericSignature, Destructor, DidSet, DifferentiableFunctionType,
    DirectMethodReferenceAttribute, Directness, DispatchThunk, DistributedAccessor, DistributedThunk, DroppedArgument,
    DynamicAttribute, DynamicSelf, DynamicallyReplaceableFunctionImpl, DynamicallyReplaceableFunctionKey,
    DynamicallyReplaceableFunctionVar, EmptyList, Enum, EnumCase, ErrorType, EscapingAutoClosureType, EscapingObjCBlock,
    ExistentialMetatype, ExplicitClosure, Extension, ExtensionAttachedMacroExpansion, ExtensionDescriptor, FieldOffset,
    FirstElementMarker, FreestandingMacroExpansion, FullObjCResilientClassStub, FullTypeMetadata, Function,
    FunctionSignatureSpecialization, FunctionSignatureSpecializationParam, FunctionSignatureSpecializationParamKind,
    FunctionSignatureSpecializationParamPayload, FunctionSignatureSpecializationReturn, FunctionType,
    GenericPartialSpecialization, GenericPartialSpecializationNotReAbstracted, GenericProtocolWitnessTable,
    GenericProtocolWitnessTableInstantiationFunction, GenericSpecialization, GenericSpecializationInResilienceDomain,
    GenericSpecializationNotReAbstracted, GenericSpecializationParam, GenericSpecializationPrespecialized,
    GenericTypeMetadataPattern, GenericTypeParamDecl, Getter, Global, GlobalActorFunctionType, GlobalGetter,
    GlobalVariableOnceDeclList, GlobalVariableOnceFunction, GlobalVariableOnceToken, HasSymbolQuery, IVarDestroyer,
    IVarInitializer, Identifier, ImplConvention, ImplCoroutineKind, ImplDifferentiabilityKind, ImplErasedIsolation,
    ImplErrorResult, ImplEscaping, ImplFunctionAttribute, ImplFunctionConvention, ImplFunctionConventionName,
    ImplFunctionType, ImplInvocationSubstitutions, ImplParameter, ImplParameterImplicitLeading, ImplParameterIsolated,
    ImplParameterResultDifferentiability, ImplParameterSending, ImplPatternSubstitutions, ImplResult, ImplSendingResult,
    ImplYield, ImplicitClosure, InOut, Index, InfixOperator, InitAccessor, Initializer, InlinedGenericFunction, IsSerialized,
    Isolated, IsolatedAnyFunctionType, IsolatedDeallocator, KeyPathEqualsThunkHelper, KeyPathGetterThunkHelper,
    KeyPathHashThunkHelper, KeyPathSetterThunkHelper, LabelList, LazyProtocolWitnessTableAccessor,
    LazyProtocolWitnessTableCacheVariable, LocalDeclName, Macro, MacroExpansionLoc, MacroExpansionUniqueName,
    MaterializeForSet, MemberAttachedMacroExpansion, MemberAttributeAttachedMacroExpansion, MergedFunction, Metaclass,
    MetadataInstantiationCache, Metatype, MetatypeParamsRemoved, MetatypeRepresentation, MethodDescriptor,
    MethodLookupFunction, Modify2Accessor, ModifyAccessor, Module, ModuleDescriptor, NativeOwningAddressor,
    NativeOwningMutableAddressor, NativePinningAddressor, NativePinningMutableAddressor, NoDerivative, NoEscapeFunctionType,
    NominalTypeDescriptor, NominalTypeDescriptorRecord, NonIsolatedCallerFunctionType, NonObjCAttribute,
    NoncanonicalSpecializedGenericTypeMetadata, NoncanonicalSpecializedGenericTypeMetadataCache, Number,
    ObjCAsyncCompletionHandlerImpl, ObjCAttribute, ObjCBlock, ObjCMetadataUpdateFunction, ObjCResilientClassStub,
    ObjectiveCProtocolSymbolicReference, OpaqueReturnType, OpaqueReturnTypeIndex, OpaqueReturnTypeOf, OpaqueType,
    OpaqueTypeDescriptor, OpaqueTypeDescriptorAccessor, OpaqueTypeDescriptorAccessorImpl, OpaqueTypeDescriptorAccessorKey,
    OpaqueTypeDescriptorAccessorVar, OpaqueTypeDescriptorRecord, OtherNominalType, OutlinedAssignWithCopy,
    OutlinedAssignWithCopyNoValueWitness, OutlinedAssignWithTake, OutlinedAssignWithTakeNoValueWitness,
    OutlinedBridgedMethod, OutlinedConsume, OutlinedCopy, OutlinedDestroy, OutlinedDestroyNoValueWitness,
    OutlinedEnumGetTag, OutlinedEnumProjectDataForLoad, OutlinedEnumTagStore, OutlinedInitializeWithCopy,
    OutlinedInitializeWithCopyNoValueWitness, OutlinedInitializeWithTake, OutlinedInitializeWithTakeNoValueWitness,
    OutlinedReadOnlyObject, OutlinedRelease, OutlinedRetain, OutlinedVariable, Owned, OwningAddressor,
    OwningMutableAddressor, Pack, PackElement, PackElementLevel, PackExpansion, PackProtocolConformance,
    PartialApplyForwarder, PartialApplyObjCForwarder, PeerAttachedMacroExpansion, PostfixOperator,
    PreambleAttachedMacroExpansion, PredefinedObjCAsyncCompletionHandlerImpl, PrefixOperator, PrivateDeclName,
    PropertyDescriptor, PropertyWrappedFieldInitAccessor, PropertyWrapperBackingInitializer,
    PropertyWrapperInitFromProjectedValue, Protocol, ProtocolConformance, ProtocolConformanceDescriptor,
    ProtocolConformanceDescriptorRecord, ProtocolConformanceRefInOtherModule, ProtocolConformanceRefInProtocolModule,
    ProtocolConformanceRefInTypeModule, ProtocolDescriptor, ProtocolDescriptorRecord, ProtocolList,
    ProtocolListWithAnyObject, ProtocolListWithClass, ProtocolRequirementsBaseDescriptor, ProtocolSelfConformanceDescriptor,
    ProtocolSelfConformanceWitness, ProtocolSelfConformanceWitnessTable, ProtocolSymbolicReference, ProtocolWitness,
    ProtocolWitnessTable, ProtocolWitnessTableAccessor, ProtocolWitnessTablePattern, ReabstractionThunk,
    ReabstractionThunkHelper, ReabstractionThunkHelperWithGlobalActor, ReabstractionThunkHelperWithSelf, Read2Accessor,
    ReadAccessor, ReflectionMetadataAssocTypeDescriptor, ReflectionMetadataBuiltinDescriptor,
    ReflectionMetadataFieldDescriptor, ReflectionMetadataSuperclassDescriptor, RelatedEntityDeclName,
    ResilientProtocolWitnessTable, RetroactiveConformance, ReturnType, SILBoxImmutableField, SILBoxLayout,
    SILBoxMutableField, SILBoxType, SILBoxTypeWithLayout, SILThunkHopToMainActorIfNeeded, SILThunkIdentity, Sending,
    SendingResultFunctionType, Setter, Shared, SpecializationPassID, Static, Structure, Subscript, Suffix, SugaredArray,
    SugaredDictionary, SugaredOptional, SugaredParen, ThinFunctionType, ThrowsAnnotation, Tuple, TupleElement,
    TupleElementName, Type, TypeAlias, TypeList, TypeMangling, TypeMetadata, TypeMetadataAccessFunction,
    TypeMetadataCompletionFunction, TypeMetadataDemanglingCache, TypeMetadataInstantiationCache,
    TypeMetadataInstantiationFunction, TypeMetadataLazyCache, TypeMetadataMangledNameRef,
    TypeMetadataSingletonInitializationCache, TypeSymbolicReference, TypedThrowsAnnotation, UncurriedFunctionType,
    Uniquable, UnknownIndex, Unmanaged, Unowned, UnsafeAddressor, UnsafeMutableAddressor, VTableAttribute, VTableThunk,
    ValueWitness, ValueWitnessTable, Variable, VariadicMarker, Weak, WillSet,
}

use Kind as K;

pub type NodeId = u32;

/// The children of a node: up to four kept in place (most nodes have fewer), more on the heap.
#[derive(Clone, Debug, Default)]
struct Children {
    len: u32,
    inline: [NodeId; 4],
    heap: Vec<NodeId>,
}

impl Children {
    fn as_slice(&self) -> &[NodeId] {
        let len = self.len as usize;
        if len <= 4 {
            &self.inline[..len]
        } else {
            &self.heap
        }
    }
    fn as_mut_slice(&mut self) -> &mut [NodeId] {
        let len = self.len as usize;
        if len <= 4 {
            &mut self.inline[..len]
        } else {
            &mut self.heap
        }
    }
    fn push(&mut self, c: NodeId) {
        let len = self.len as usize;
        if len < 4 {
            self.inline[len] = c;
        } else {
            if len == 4 {
                self.heap.reserve(8);
                self.heap.extend_from_slice(&self.inline);
            }
            self.heap.push(c);
        }
        self.len += 1;
    }
}

/// A node without text.
const NO_TEXT: u32 = u32::MAX;

/// A node of the tree: its kind, its text (a range of the tree's text) or its number, and its children.
#[derive(Clone, Debug)]
struct Node {
    kind: Kind,
    text_at: u32,
    text_len: u32,
    index: Option<i64>,
    children: Children,
}

/// The tree of a symbol: its nodes, the text they hold, and which one is the root.
#[derive(Clone, Debug)]
pub struct Tree {
    nodes: Vec<Node>,
    texts: String,
    pub root: NodeId,
}

impl Tree {
    pub fn kind(&self, n: NodeId) -> Kind {
        self.nodes[n as usize].kind
    }
    pub fn text(&self, n: NodeId) -> Option<&str> {
        let node = &self.nodes[n as usize];
        if node.text_len == NO_TEXT {
            return None;
        }
        let at = node.text_at as usize;
        Some(&self.texts[at..at + node.text_len as usize])
    }
    pub fn index(&self, n: NodeId) -> Option<i64> {
        self.nodes[n as usize].index
    }
    pub fn children(&self, n: NodeId) -> &[NodeId] {
        self.nodes[n as usize].children.as_slice()
    }
}

type N = Option<NodeId>;

/// The standard types `S<letter>` names.
fn standard(c: u8) -> Option<(Kind, &'static str)> {
    Some(match c {
        b'A' => (K::Structure, "AutoreleasingUnsafeMutablePointer"),
        b'a' => (K::Structure, "Array"),
        b'b' => (K::Structure, "Bool"),
        b'D' => (K::Structure, "Dictionary"),
        b'd' => (K::Structure, "Double"),
        b'f' => (K::Structure, "Float"),
        b'h' => (K::Structure, "Set"),
        b'I' => (K::Structure, "DefaultIndices"),
        b'i' => (K::Structure, "Int"),
        b'J' => (K::Structure, "Character"),
        b'N' => (K::Structure, "ClosedRange"),
        b'n' => (K::Structure, "Range"),
        b'O' => (K::Structure, "ObjectIdentifier"),
        b'P' => (K::Structure, "UnsafePointer"),
        b'p' => (K::Structure, "UnsafeMutablePointer"),
        b'R' => (K::Structure, "UnsafeBufferPointer"),
        b'r' => (K::Structure, "UnsafeMutableBufferPointer"),
        b'S' => (K::Structure, "String"),
        b's' => (K::Structure, "Substring"),
        b'u' => (K::Structure, "UInt"),
        b'V' => (K::Structure, "UnsafeRawPointer"),
        b'v' => (K::Structure, "UnsafeMutableRawPointer"),
        b'W' => (K::Structure, "UnsafeRawBufferPointer"),
        b'w' => (K::Structure, "UnsafeMutableRawBufferPointer"),
        b'q' => (K::Enum, "Optional"),
        b'B' => (K::Protocol, "BinaryFloatingPoint"),
        b'E' => (K::Protocol, "Encodable"),
        b'e' => (K::Protocol, "Decodable"),
        b'F' => (K::Protocol, "FloatingPoint"),
        b'G' => (K::Protocol, "RandomNumberGenerator"),
        b'H' => (K::Protocol, "Hashable"),
        b'j' => (K::Protocol, "Numeric"),
        b'K' => (K::Protocol, "BidirectionalCollection"),
        b'k' => (K::Protocol, "RandomAccessCollection"),
        b'L' => (K::Protocol, "Comparable"),
        b'l' => (K::Protocol, "Collection"),
        b'M' => (K::Protocol, "MutableCollection"),
        b'm' => (K::Protocol, "RangeReplaceableCollection"),
        b'Q' => (K::Protocol, "Equatable"),
        b'T' => (K::Protocol, "Sequence"),
        b't' => (K::Protocol, "IteratorProtocol"),
        b'U' => (K::Protocol, "UnsignedInteger"),
        b'X' => (K::Protocol, "RangeExpression"),
        b'x' => (K::Protocol, "Strideable"),
        b'Y' => (K::Protocol, "RawRepresentable"),
        b'y' => (K::Protocol, "StringProtocol"),
        b'Z' => (K::Protocol, "SignedInteger"),
        b'z' => (K::Protocol, "BinaryInteger"),
        _ => return None,
    })
}

/// The concurrency types `Sc<letter>` names.
fn concurrency(c: u8) -> Option<(Kind, &'static str)> {
    Some(match c {
        b'A' => (K::Protocol, "Actor"),
        b'C' => (K::Structure, "CheckedContinuation"),
        b'c' => (K::Structure, "UnsafeContinuation"),
        b'E' => (K::Structure, "CancellationError"),
        b'e' => (K::Structure, "UnownedSerialExecutor"),
        b'F' => (K::Protocol, "Executor"),
        b'f' => (K::Protocol, "SerialExecutor"),
        b'G' => (K::Structure, "TaskGroup"),
        b'g' => (K::Structure, "ThrowingTaskGroup"),
        b'h' => (K::Protocol, "TaskExecutor"),
        b'I' => (K::Protocol, "AsyncIteratorProtocol"),
        b'i' => (K::Protocol, "AsyncSequence"),
        b'J' => (K::Structure, "UnownedJob"),
        b'M' => (K::Class, "MainActor"),
        b'P' => (K::Structure, "TaskPriority"),
        b'S' => (K::Structure, "AsyncStream"),
        b's' => (K::Structure, "AsyncThrowingStream"),
        b'T' => (K::Structure, "Task"),
        b't' => (K::Structure, "UnsafeCurrentTask"),
        _ => return None,
    })
}

/// Value witnesses (`w<two letters>`), as the printer names them.
fn value_witness(a: u8, b: u8) -> Option<&'static str> {
    Some(match [a, b] {
        [b'a', b'l'] => "allocateBuffer",
        [b'c', b'a'] => "assignWithCopy",
        [b't', b'a'] => "assignWithTake",
        [b'd', b'e'] => "deallocateBuffer",
        [b'x', b'x'] => "destroy",
        [b'X', b'X'] => "destroyBuffer",
        [b'X', b'x'] => "destroyArray",
        [b'C', b'P'] => "initializeBufferWithCopyOfBuffer",
        [b'C', b'p'] => "initializeBufferWithCopy",
        [b'c', b'p'] => "initializeWithCopy",
        [b'T', b'k'] => "initializeBufferWithTake",
        [b't', b'k'] => "initializeWithTake",
        [b'p', b'r'] => "projectBuffer",
        [b'T', b'K'] => "initializeBufferWithTakeOfBuffer",
        [b'C', b'c'] => "initializeArrayWithCopy",
        [b'T', b't'] => "initializeArrayWithTakeFrontToBack",
        [b't', b'T'] => "initializeArrayWithTakeBackToFront",
        [b'x', b's'] => "storeExtraInhabitant",
        [b'x', b'g'] => "getExtraInhabitantIndex",
        [b'u', b'g'] => "getEnumTag",
        [b'u', b'p'] => "destructiveProjectEnumData",
        [b'u', b'i'] => "destructiveInjectEnumTag",
        [b'e', b't'] => "getEnumTagSinglePayload",
        [b's', b't'] => "storeEnumTagSinglePayload",
        _ => return None,
    })
}

fn is_context(k: Kind) -> bool {
    matches!(
        k,
        K::Allocator
            | K::AnonymousContext
            | K::Class
            | K::Constructor
            | K::Deallocator
            | K::IsolatedDeallocator
            | K::DefaultArgumentInitializer
            | K::Destructor
            | K::DidSet
            | K::Enum
            | K::ExplicitClosure
            | K::Extension
            | K::Function
            | K::Getter
            | K::GlobalGetter
            | K::IVarInitializer
            | K::IVarDestroyer
            | K::ImplicitClosure
            | K::Initializer
            | K::InitAccessor
            | K::MaterializeForSet
            | K::ModifyAccessor
            | K::Modify2Accessor
            | K::Module
            | K::NativeOwningAddressor
            | K::NativeOwningMutableAddressor
            | K::NativePinningAddressor
            | K::NativePinningMutableAddressor
            | K::OtherNominalType
            | K::OwningAddressor
            | K::OwningMutableAddressor
            | K::PropertyWrapperBackingInitializer
            | K::PropertyWrapperInitFromProjectedValue
            | K::PropertyWrappedFieldInitAccessor
            | K::Protocol
            | K::ProtocolSymbolicReference
            | K::ReadAccessor
            | K::Read2Accessor
            | K::Setter
            | K::Static
            | K::Structure
            | K::Subscript
            | K::TypeSymbolicReference
            | K::TypeAlias
            | K::UnsafeAddressor
            | K::UnsafeMutableAddressor
            | K::Variable
            | K::WillSet
            | K::OpaqueReturnTypeOf
            | K::AutoDiffFunction
            | K::AccessorAttachedMacroExpansion
            | K::MemberAttributeAttachedMacroExpansion
            | K::MemberAttachedMacroExpansion
            | K::PeerAttachedMacroExpansion
            | K::ConformanceAttachedMacroExpansion
            | K::ExtensionAttachedMacroExpansion
            | K::PreambleAttachedMacroExpansion
            | K::BodyAttachedMacroExpansion
            | K::FreestandingMacroExpansion
            | K::MacroExpansionUniqueName
            | K::MacroExpansionLoc
            | K::Macro
            | K::GenericTypeParamDecl
            | K::BuiltinTupleType
    )
}

fn is_macro_expansion(k: Kind) -> bool {
    matches!(
        k,
        K::AccessorAttachedMacroExpansion
            | K::MemberAttributeAttachedMacroExpansion
            | K::FreestandingMacroExpansion
            | K::MemberAttachedMacroExpansion
            | K::PeerAttachedMacroExpansion
            | K::ConformanceAttachedMacroExpansion
            | K::ExtensionAttachedMacroExpansion
            | K::MacroExpansionLoc
            | K::BodyAttachedMacroExpansion
            | K::PreambleAttachedMacroExpansion
    )
}

fn is_function_attr(k: Kind) -> bool {
    matches!(
        k,
        K::FunctionSignatureSpecialization
            | K::GenericSpecialization
            | K::GenericSpecializationPrespecialized
            | K::InlinedGenericFunction
            | K::GenericSpecializationNotReAbstracted
            | K::GenericPartialSpecialization
            | K::GenericPartialSpecializationNotReAbstracted
            | K::GenericSpecializationInResilienceDomain
            | K::ObjCAttribute
            | K::NonObjCAttribute
            | K::DynamicAttribute
            | K::DirectMethodReferenceAttribute
            | K::VTableAttribute
            | K::PartialApplyForwarder
            | K::PartialApplyObjCForwarder
            | K::OutlinedVariable
            | K::OutlinedReadOnlyObject
            | K::OutlinedBridgedMethod
            | K::MergedFunction
            | K::DistributedThunk
            | K::DistributedAccessor
            | K::DynamicallyReplaceableFunctionImpl
            | K::DynamicallyReplaceableFunctionKey
            | K::DynamicallyReplaceableFunctionVar
            | K::AsyncFunctionPointer
            | K::AsyncAwaitResumePartialFunction
            | K::AsyncSuspendResumePartialFunction
            | K::AccessibleFunctionRecord
            | K::BackDeploymentThunk
            | K::BackDeploymentFallback
            | K::HasSymbolQuery
            | K::CoroFunctionPointer
            | K::DefaultOverride
    )
}

fn is_decl_name(k: Kind) -> bool {
    matches!(
        k,
        K::Identifier
            | K::LocalDeclName
            | K::PrivateDeclName
            | K::RelatedEntityDeclName
            | K::PrefixOperator
            | K::PostfixOperator
            | K::InfixOperator
            | K::TypeSymbolicReference
            | K::ProtocolSymbolicReference
    )
}

fn is_any_generic(k: Kind) -> bool {
    matches!(
        k,
        K::Structure | K::Class | K::Enum | K::Protocol | K::ProtocolSymbolicReference | K::OtherNominalType | K::TypeAlias | K::TypeSymbolicReference | K::BuiltinTupleType
    )
}

fn is_requirement(k: Kind) -> bool {
    matches!(
        k,
        K::DependentGenericParamPackMarker
            | K::DependentGenericParamValueMarker
            | K::DependentGenericSameTypeRequirement
            | K::DependentGenericSameShapeRequirement
            | K::DependentGenericLayoutRequirement
            | K::DependentGenericConformanceRequirement
            | K::DependentGenericInverseConformanceRequirement
    )
}

fn is_any_conformance(k: Kind) -> bool {
    matches!(
        k,
        K::ConcreteProtocolConformance
            | K::PackProtocolConformance
            | K::DependentProtocolConformanceRoot
            | K::DependentProtocolConformanceInherited
            | K::DependentProtocolConformanceAssociated
    )
}

fn is_dependent_conformance(k: Kind) -> bool {
    matches!(k, K::DependentProtocolConformanceRoot | K::DependentProtocolConformanceInherited | K::DependentProtocolConformanceAssociated)
}

/// Function signature specialization parameter kinds: the low six bits a kind, the bits above it options.
mod fss {
    pub const CONSTANT_PROP_FUNCTION: i64 = 0;
    pub const CONSTANT_PROP_GLOBAL: i64 = 1;
    pub const CONSTANT_PROP_INTEGER: i64 = 2;
    pub const CONSTANT_PROP_FLOAT: i64 = 3;
    pub const CONSTANT_PROP_STRING: i64 = 4;
    pub const CLOSURE_PROP: i64 = 5;
    pub const BOX_TO_VALUE: i64 = 6;
    pub const BOX_TO_STACK: i64 = 7;
    pub const IN_OUT_TO_OUT: i64 = 8;
    pub const CONSTANT_PROP_KEY_PATH: i64 = 9;
    pub const CLOSURE_PROP_PREVIOUS_ARG: i64 = 10;
    pub const CLOSURE_PROP_ESCAPING: i64 = 11;
    pub const DEAD: i64 = 1 << 6;
    pub const OWNED_TO_GUARANTEED: i64 = 1 << 7;
    pub const SROA: i64 = 1 << 8;
    pub const GUARANTEED_TO_OWNED: i64 = 1 << 9;
    pub const EXISTENTIAL_TO_GENERIC: i64 = 1 << 10;
}

/// A code unit as the parser compares it: ASCII as itself, anything else as 0x80
/// (which no rule names), and 0 past the end (JavaScript's '').
fn unit(c: Option<&u8>) -> u8 {
    c.copied().unwrap_or(0)
}

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}
fn is_lower(c: u8) -> bool {
    c.is_ascii_lowercase()
}
fn is_upper(c: u8) -> bool {
    c.is_ascii_uppercase()
}
fn is_letter(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

/// Words of an identifier, for the word substitutions after it.
fn is_word_start(c: Option<u8>) -> bool {
    match c {
        None => false,
        Some(c) => !c.is_ascii_digit() && c != b'_',
    }
}
fn is_word_end(c: Option<u8>, prev: u8) -> bool {
    match c {
        None => true,
        Some(c) => c == b'_' || (!prev.is_ascii_uppercase() && c.is_ascii_uppercase()),
    }
}

/// How deep bound generic arguments may nest in the parser. Deeper than the
/// printer goes (768) anyway, so a name past it was never printed.
const MAX_GENERIC_NESTING: u32 = 1024;

struct Demangler<'a> {
    u: &'a Units<'a>,
    s: &'a [u8],
    pos: usize,
    stack: Vec<NodeId>,
    subs: Vec<NodeId>,
    /// Words seen in identifiers, as ranges of the name.
    words: Vec<(usize, usize)>,
    steps: u32,
    t: Tree,
    /// The code units of the identifier being read.
    scratch: Vec<u16>,
    /// A malformed tree was met (the TypeScript threw): the name does not parse.
    bad: bool,
    nesting: u32,
}

impl<'a> Demangler<'a> {
    fn new(u: &'a Units<'a>) -> Self {
        let t = Tree { nodes: Vec::with_capacity(u.len().max(16)), texts: String::with_capacity(u.len() * 2), root: 0 };
        let (stack, subs, words) = (Vec::with_capacity(16), Vec::with_capacity(16), Vec::with_capacity(26));
        Demangler { u, s: &u.bytes, pos: 0, stack, subs, words, steps: 0, t, scratch: Vec::new(), bad: false, nesting: 0 }
    }

    fn peek(&self) -> u8 {
        unit(self.s.get(self.pos))
    }
    /// The next unit; the position moves on even past the end, as `this.s[this.pos++]` did.
    fn next(&mut self) -> u8 {
        let c = self.peek();
        self.pos += 1;
        c
    }
    fn next_if(&mut self, p: &[u8]) -> bool {
        if self.s.get(self.pos..).unwrap_or(&[]).starts_with(p) {
            self.pos += p.len();
            return true;
        }
        false
    }
    fn back(&mut self) {
        self.pos -= 1;
    }

    fn kind(&self, n: NodeId) -> Kind {
        self.t.nodes[n as usize].kind
    }
    fn count(&self, n: NodeId) -> usize {
        self.t.nodes[n as usize].children.len as usize
    }
    fn text(&self, n: NodeId) -> Option<&str> {
        self.t.text(n)
    }
    fn first(&mut self, n: NodeId) -> NodeId {
        self.child(n, 0)
    }
    fn child(&mut self, n: NodeId, i: usize) -> NodeId {
        match self.t.children(n).get(i) {
            Some(&c) => c,
            None => {
                self.bad = true;
                n
            }
        }
    }

    /// A node over the text at `text_at..text_at + text_len` of the tree's text (NO_TEXT: none).
    fn make_at(&mut self, kind: Kind, text_at: usize, text_len: u32, index: Option<i64>) -> NodeId {
        self.t.nodes.push(Node { kind, text_at: text_at as u32, text_len, index, children: Children::default() });
        (self.t.nodes.len() - 1) as NodeId
    }
    /// A node over the text written to the tree's text since `at`.
    fn make_since(&mut self, kind: Kind, at: usize) -> NodeId {
        let len = (self.t.texts.len() - at) as u32;
        self.make_at(kind, at, len, None)
    }
    fn make(&mut self, kind: Kind, text: Option<&str>, index: Option<i64>) -> NodeId {
        match text {
            Some(text) => {
                let at = self.t.texts.len();
                self.t.texts.push_str(text);
                self.make_at(kind, at, text.len() as u32, index)
            }
            None => self.make_at(kind, 0, NO_TEXT, index),
        }
    }
    fn node(&mut self, kind: Kind) -> NodeId {
        self.make(kind, None, None)
    }
    fn node_text(&mut self, kind: Kind, text: &str) -> NodeId {
        self.make(kind, Some(text), None)
    }
    /// A node whose text is one ASCII character.
    fn node_char(&mut self, kind: Kind, c: u8) -> NodeId {
        let at = self.t.texts.len();
        self.t.texts.push(c as char);
        self.make_since(kind, at)
    }
    fn extend_children(&mut self, parent: NodeId, children: &[NodeId]) {
        for &c in children {
            self.push_child(parent, c);
        }
    }
    fn children_of(&self, n: NodeId) -> Vec<NodeId> {
        self.t.children(n).to_vec()
    }
    fn node_index(&mut self, kind: Kind, index: i64) -> NodeId {
        self.make(kind, None, Some(index))
    }
    fn push_child(&mut self, parent: NodeId, child: NodeId) {
        self.t.nodes[parent as usize].children.push(child);
    }
    fn with(&mut self, kind: Kind, children: &[N]) -> N {
        if children.iter().any(Option::is_none) {
            return None;
        }
        let n = self.node(kind);
        for c in children {
            self.push_child(n, c.unwrap());
        }
        Some(n)
    }
    fn type_(&mut self, child: N) -> N {
        self.with(K::Type, &[child])
    }
    /// Adds a child; with either one missing the result is missing too.
    fn add(&mut self, parent: N, child: N) -> N {
        let (p, c) = (parent?, child?);
        self.push_child(p, c);
        Some(p)
    }
    /// Adds a child if there is one.
    fn add_if(&mut self, parent: NodeId, child: N) {
        if let Some(c) = child {
            self.push_child(parent, c);
        }
    }
    fn change_kind(&mut self, n: N, kind: Kind) -> N {
        let mut copy = self.t.nodes[n? as usize].clone();
        copy.kind = kind;
        self.t.nodes.push(copy);
        Some((self.t.nodes.len() - 1) as NodeId)
    }
    fn swift_type(&mut self, kind: Kind, name: &str) -> NodeId {
        let module = self.node_text(K::Module, "Swift");
        let ident = self.node_text(K::Identifier, name);
        let t = self.with(kind, &[Some(module), Some(ident)]);
        self.type_(t).unwrap()
    }
    fn reverse_children(&mut self, n: NodeId) {
        self.t.nodes[n as usize].children.as_mut_slice().reverse();
    }

    fn push(&mut self, n: NodeId) {
        self.stack.push(n);
    }
    fn pop(&mut self) -> N {
        self.stack.pop()
    }
    fn pop_kind(&mut self, kind: Kind) -> N {
        self.pop_if(|k| k == kind)
    }
    fn pop_if(&mut self, test: impl Fn(Kind) -> bool) -> N {
        let &top = self.stack.last()?;
        if !test(self.kind(top)) {
            return None;
        }
        self.stack.pop()
    }
    fn pop_type_child(&mut self) -> N {
        let t = self.pop_kind(K::Type)?;
        self.t.children(t).first().copied()
    }
    fn pop_any_generic(&mut self) -> N {
        let c = self.pop_type_child()?;
        if is_any_generic(self.kind(c)) {
            Some(c)
        } else {
            None
        }
    }
    fn pop_module(&mut self) -> N {
        if let Some(ident) = self.pop_kind(K::Identifier) {
            return self.change_kind(Some(ident), K::Module);
        }
        self.pop_kind(K::Module)
    }
    fn pop_context(&mut self) -> N {
        if let Some(module) = self.pop_module() {
            return Some(module);
        }
        if let Some(t) = self.pop_kind(K::Type) {
            if self.count(t) != 1 {
                return None;
            }
            let first = self.first(t);
            if !is_context(self.kind(first)) {
                return None;
            }
            return Some(first);
        }
        self.pop_if(is_context)
    }
    fn pop_entity(&mut self) -> N {
        self.pop_if(|k| k == K::Type || is_context(k))
    }
    fn add_sub(&mut self, n: N) {
        if let Some(n) = n {
            self.subs.push(n);
        }
    }

    fn natural(&mut self) -> i64 {
        if !is_digit(self.peek()) {
            return -1000;
        }
        let mut n: i64 = 0;
        while is_digit(self.peek()) {
            n = n * 10 + (self.next() - b'0') as i64;
            if n > 0x7fff_ffff {
                return -1000;
            }
        }
        n
    }
    fn index(&mut self) -> i64 {
        if self.next_if(b"_") {
            return 0;
        }
        let n = self.natural();
        if n >= 0 && self.next_if(b"_") {
            return n + 1;
        }
        -1000
    }
    fn index_node(&mut self) -> N {
        let i = self.index();
        if i >= 0 {
            Some(self.node_index(K::Number, i))
        } else {
            None
        }
    }

    fn demangle_symbol(&mut self) -> N {
        let starts = |p: &[u8]| self.s.starts_with(p);
        if starts(b"_$s") || starts(b"_$S") || starts(b"_$e") {
            self.pos = 3;
        } else if starts(b"$s") || starts(b"$S") || starts(b"$e") {
            self.pos = 2;
        } else {
            return None;
        }
        while self.pos < self.s.len() {
            self.steps += 1;
            if self.steps > 20000 {
                return None;
            }
            let n = self.operator();
            if self.bad {
                return None;
            }
            self.push(n?);
        }
        let top = self.node(K::Global);
        let suffix = self.pop_kind(K::Suffix);
        let mut parent = top;
        while let Some(attr) = self.pop_if(is_function_attr) {
            self.push_child(parent, attr);
            if matches!(self.kind(attr), K::PartialApplyForwarder | K::PartialApplyObjCForwarder) {
                parent = attr;
            }
        }
        for i in 0..self.stack.len() {
            let n = self.stack[i];
            let n = if self.kind(n) == K::Type { self.first(n) } else { n };
            self.push_child(parent, n);
        }
        if let Some(suffix) = suffix {
            self.push_child(top, suffix);
        }
        if self.bad || self.count(top) == 0 {
            return None;
        }
        Some(top)
    }

    fn operator(&mut self) -> N {
        let c = self.next();
        match c {
            b'A' => self.multi_substitutions(),
            b'B' => self.builtin_type(),
            b'C' => self.any_generic_type(K::Class),
            b'D' => {
                let t = self.pop_kind(K::Type);
                self.with(K::TypeMangling, &[t])
            }
            b'E' => self.extension_context(),
            b'F' => self.plain_function(),
            b'G' => self.bound_generic_type(),
            b'H' => match self.next() {
                b'A' => self.dependent_conformance_associated(),
                b'C' => self.concrete_conformance(),
                b'D' => self.dependent_conformance_root(),
                b'I' => self.dependent_conformance_inherited(),
                b'P' => {
                    let p = self.pop_protocol();
                    self.with(K::ProtocolConformanceRefInTypeModule, &[p])
                }
                b'p' => {
                    let p = self.pop_protocol();
                    self.with(K::ProtocolConformanceRefInProtocolModule, &[p])
                }
                b'X' => {
                    let list = self.pop_any_conformance_list();
                    self.with(K::PackProtocolConformance, &[list])
                }
                b'c' => {
                    let conf = self.pop_conformance();
                    self.with(K::ProtocolConformanceDescriptorRecord, &[conf])
                }
                b'n' => {
                    let t = self.pop_kind(K::Type);
                    self.with(K::NominalTypeDescriptorRecord, &[t])
                }
                b'o' => {
                    let n = self.pop();
                    self.with(K::OpaqueTypeDescriptorRecord, &[n])
                }
                b'r' => {
                    let p = self.pop_protocol();
                    self.with(K::ProtocolDescriptorRecord, &[p])
                }
                b'F' => Some(self.node(K::AccessibleFunctionRecord)),
                _ => {
                    self.back();
                    self.back();
                    self.identifier()
                }
            },
            b'I' => self.impl_function_type(),
            b'K' => Some(self.node(K::ThrowsAnnotation)),
            b'L' => self.local_identifier(),
            b'M' => self.metatype(),
            b'N' => {
                let t = self.pop_kind(K::Type);
                self.with(K::TypeMetadata, &[t])
            }
            b'O' => self.any_generic_type(K::Enum),
            b'P' => self.any_generic_type(K::Protocol),
            b'Q' => self.archetype(),
            b'R' => self.generic_requirement(),
            b'S' => self.standard_substitution(),
            b'T' => self.thunk_or_specialization(),
            b'V' => self.any_generic_type(K::Structure),
            b'W' => self.witness(),
            b'X' => self.special_type(),
            b'Y' => self.type_annotation(),
            b'Z' => {
                let e = self.pop_entity();
                self.with(K::Static, &[e])
            }
            b'a' => self.any_generic_type(K::TypeAlias),
            b'c' => self.pop_function_type(K::FunctionType, false),
            b'd' => Some(self.node(K::VariadicMarker)),
            b'f' => self.function_entity(),
            b'g' => self.retroactive_conformance(),
            b'h' => {
                let c = self.pop_type_child();
                let shared = self.with(K::Shared, &[c]);
                self.type_(shared)
            }
            b'i' => self.subscript(),
            b'l' => self.generic_signature(false),
            b'm' => {
                let t = self.pop_kind(K::Type);
                let m = self.with(K::Metatype, &[t]);
                self.type_(m)
            }
            b'n' => {
                let c = self.pop_type_child();
                let owned = self.with(K::Owned, &[c]);
                self.type_(owned)
            }
            b'o' => self.operator_identifier(),
            b'p' => {
                let list = self.protocol_list();
                self.type_(list)
            }
            b'q' => {
                let p = self.generic_param_index();
                self.type_(p)
            }
            b'r' => self.generic_signature(true),
            b's' => Some(self.node_text(K::Module, "Swift")),
            b't' => self.pop_tuple(),
            b'u' => self.generic_type(),
            b'v' => self.variable(),
            b'w' => self.value_witness(),
            b'x' => {
                let p = self.generic_param(0, 0);
                self.type_(p)
            }
            b'y' => Some(self.node(K::EmptyList)),
            b'z' => {
                let c = self.pop_type_child();
                let inout = self.with(K::InOut, &[c]);
                self.type_(inout)
            }
            b'_' => Some(self.node(K::FirstElementMarker)),
            b'.' => {
                self.back();
                Some(self.suffix())
            }
            0 => None,
            _ => {
                self.back();
                self.identifier()
            }
        }
    }

    fn suffix(&mut self) -> NodeId {
        let at = self.t.texts.len();
        self.u.push_text(&mut self.t.texts, self.pos, self.s.len());
        self.pos = self.s.len();
        self.make_since(K::Suffix, at)
    }

    fn identifier(&mut self) -> N {
        let mut word_substs = false;
        let mut punycoded = false;
        if !is_digit(self.peek()) {
            return None;
        }
        if self.peek() == b'0' {
            self.next();
            if self.peek() == b'0' {
                self.next();
                punycoded = true;
            } else {
                word_substs = true;
            }
        }
        let s = self.s;
        // An ASCII name's pieces go straight into the tree's text; others gather as code units first.
        let direct = self.u.is_ascii() && !punycoded;
        let at = self.t.texts.len();
        let mut ident = core::mem::take(&mut self.scratch);
        ident.clear();
        let found = self.identifier_units(s, &mut ident, direct, word_substs, punycoded);
        if found.is_some() && !direct {
            push_utf16(&mut self.t.texts, &ident);
        }
        self.scratch = ident;
        if found.is_none() || self.t.texts.len() == at {
            self.t.texts.truncate(at);
            return None;
        }
        let n = self.make_since(K::Identifier, at);
        self.add_sub(Some(n));
        Some(n)
    }

    /// Appends the units `a..b` of the name to the identifier being read.
    fn put(&mut self, ident: &mut Vec<u16>, direct: bool, a: usize, b: usize) {
        if direct {
            self.u.push_text(&mut self.t.texts, a, b);
        } else {
            self.u.push_units(ident, a, b);
        }
    }

    /// The code units of an identifier: onto `ident`, or with `direct` (an ASCII name) onto the tree's text.
    fn identifier_units(&mut self, s: &[u8], ident: &mut Vec<u16>, direct: bool, mut word_substs: bool, punycoded: bool) -> Option<()> {
        loop {
            while word_substs && is_letter(self.peek()) {
                let c = self.next();
                let w = if is_lower(c) {
                    (c - b'a') as usize
                } else {
                    word_substs = false;
                    (c - b'A') as usize
                };
                let &(a, b) = self.words.get(w)?;
                self.put(ident, direct, a, b);
            }
            if self.next_if(b"0") {
                break;
            }
            let length = self.natural();
            if length <= 0 {
                return None;
            }
            if punycoded {
                self.next_if(b"_");
            }
            let length = length as usize;
            if self.pos + length > s.len() {
                return None;
            }
            let slice = &s[self.pos..self.pos + length];
            if punycoded {
                punycode(slice, ident)?;
            } else {
                self.put(ident, direct, self.pos, self.pos + length);
                let mut start: Option<usize> = None;
                for i in 0..=slice.len() {
                    let c = slice.get(i).copied();
                    if let Some(st) = start {
                        if is_word_end(c, slice[i - 1]) {
                            if i - st >= 2 && self.words.len() < 26 {
                                self.words.push((self.pos + st, self.pos + i));
                            }
                            start = None;
                        }
                    }
                    if start.is_none() && is_word_start(c) {
                        start = Some(i);
                    }
                }
            }
            self.pos += length;
            if !word_substs {
                break;
            }
        }
        Some(())
    }

    fn operator_identifier(&mut self) -> N {
        let ident = self.pop_kind(K::Identifier)?;
        const TABLE: &[u8; 26] = b"& @/= >    <*!|+?%-~   ^ .";
        let mut op = String::new();
        for c in self.text(ident).unwrap_or("").chars() {
            if c as u32 >= 0x80 {
                op.push(c);
                continue;
            }
            if !c.is_ascii_lowercase() {
                return None;
            }
            let o = TABLE[(c as u8 - b'a') as usize];
            if o == b' ' {
                return None;
            }
            op.push(o as char);
        }
        let kind = match self.next() {
            b'i' => K::InfixOperator,
            b'p' => K::PrefixOperator,
            b'P' => K::PostfixOperator,
            _ => return None,
        };
        Some(self.make(kind, Some(&op), None))
    }

    fn local_identifier(&mut self) -> N {
        if self.next_if(b"L") {
            let discriminator = self.pop_kind(K::Identifier);
            let name = self.pop_if(is_decl_name);
            return self.with(K::PrivateDeclName, &[discriminator, name]);
        }
        if self.next_if(b"l") {
            let discriminator = self.pop_kind(K::Identifier);
            return self.with(K::PrivateDeclName, &[discriminator]);
        }
        let c = self.peek();
        if (b'a'..=b'j').contains(&c) || (b'A'..=b'J').contains(&c) {
            self.next();
            let result = self.node(K::RelatedEntityDeclName);
            let ident = self.node_char(K::Identifier, c);
            self.push_child(result, ident);
            let popped = self.pop();
            return self.add(Some(result), popped);
        }
        let discriminator = self.index_node();
        let name = self.pop_if(is_decl_name);
        self.with(K::LocalDeclName, &[discriminator, name])
    }

    fn multi_substitutions(&mut self) -> N {
        let mut repeat: i64 = -1;
        loop {
            let c = self.next();
            if c == 0 {
                return None;
            }
            if is_lower(c) {
                let n = self.push_multi(repeat, (c - b'a') as i64)?;
                self.push(n);
                repeat = -1;
                continue;
            }
            if is_upper(c) {
                return self.push_multi(repeat, (c - b'A') as i64);
            }
            if c == b'_' {
                let i = repeat + 27;
                return self.subs.get(i as usize).copied();
            }
            self.back();
            repeat = self.natural();
            if repeat < 0 {
                return None;
            }
        }
    }
    fn push_multi(&mut self, mut repeat: i64, i: i64) -> N {
        let &n = self.subs.get(i as usize)?;
        if repeat > 2048 {
            return None;
        }
        while repeat > 1 {
            self.push(n);
            repeat -= 1;
        }
        Some(n)
    }

    fn standard_substitution(&mut self) -> N {
        let c = self.next();
        if c == b'o' {
            return Some(self.node_text(K::Module, "__C"));
        }
        if c == b'C' {
            return Some(self.node_text(K::Module, "__C_Synthesized"));
        }
        if c == b'g' {
            let optional = self.swift_type(K::Enum, "Optional");
            let t = self.pop_kind(K::Type);
            let list = self.with(K::TypeList, &[t]);
            let bound = self.with(K::BoundGenericEnum, &[Some(optional), list]);
            let optional = self.type_(bound);
            self.add_sub(optional);
            return optional;
        }
        self.back();
        let repeat = self.natural();
        if repeat > 2048 {
            return None;
        }
        let second = self.next_if(b"c");
        let c = self.next();
        let (kind, name) = if second { concurrency(c) } else { standard(c) }?;
        let n = self.swift_type(kind, name);
        let mut r = repeat;
        while r > 1 {
            self.push(n);
            r -= 1;
        }
        Some(n)
    }

    fn builtin_type(&mut self) -> N {
        let c = self.next();
        let t = match c {
            b'b' => self.node_text(K::BuiltinTypeName, "Builtin.BridgeObject"),
            b'B' => self.node_text(K::BuiltinTypeName, "Builtin.UnsafeValueBuffer"),
            b'e' => self.node_text(K::BuiltinTypeName, "Builtin.Executor"),
            b'f' | b'i' => {
                let size = self.index() - 1;
                if size <= 0 || size > 4096 {
                    return None;
                }
                let text = format!("{}{size}", if c == b'f' { "Builtin.FPIEEE" } else { "Builtin.Int" });
                self.make(K::BuiltinTypeName, Some(&text), None)
            }
            b'I' => self.node_text(K::BuiltinTypeName, "Builtin.IntLiteral"),
            b'v' => {
                let elements = self.index() - 1;
                if elements <= 0 || elements > 4096 {
                    return None;
                }
                let element = self.pop_type_child()?;
                if self.kind(element) != K::BuiltinTypeName {
                    return None;
                }
                let text = self.text(element).unwrap_or("");
                let rest = text.strip_prefix("Builtin.")?;
                let text = format!("Builtin.Vec{elements}x{rest}");
                self.make(K::BuiltinTypeName, Some(&text), None)
            }
            b'O' => self.node_text(K::BuiltinTypeName, "Builtin.UnknownObject"),
            b'o' => self.node_text(K::BuiltinTypeName, "Builtin.NativeObject"),
            b'p' => self.node_text(K::BuiltinTypeName, "Builtin.RawPointer"),
            b'j' => self.node_text(K::BuiltinTypeName, "Builtin.Job"),
            b'D' => self.node_text(K::BuiltinTypeName, "Builtin.DefaultActorStorage"),
            b'd' => self.node_text(K::BuiltinTypeName, "Builtin.NonDefaultDistributedActorStorage"),
            b'c' => self.node_text(K::BuiltinTypeName, "Builtin.RawUnsafeContinuation"),
            b't' => self.node_text(K::BuiltinTypeName, "Builtin.SILToken"),
            b'w' => self.node_text(K::BuiltinTypeName, "Builtin.Word"),
            b'P' => self.node_text(K::BuiltinTypeName, "Builtin.PackIndex"),
            b'T' => self.node(K::BuiltinTupleType),
            _ => return None,
        };
        self.type_(Some(t))
    }

    fn any_generic_type(&mut self, kind: Kind) -> N {
        let name = self.pop_if(is_decl_name);
        let ctx = self.pop_context();
        let g = self.with(kind, &[ctx, name]);
        let t = self.type_(g);
        self.add_sub(t);
        t
    }

    fn extension_context(&mut self) -> N {
        let sig = self.pop_kind(K::DependentGenericSignature);
        let module = self.pop_module();
        let t = self.pop_any_generic();
        let mut ext = self.with(K::Extension, &[module, t]);
        if sig.is_some() {
            ext = self.add(ext, sig);
        }
        ext
    }

    fn plain_function(&mut self) -> N {
        let sig = self.pop_kind(K::DependentGenericSignature);
        let mut t = self.pop_function_type(K::FunctionType, false);
        let labels = self.pop_function_param_labels(t);
        if sig.is_some() {
            let g = self.with(K::DependentGenericType, &[sig, t]);
            t = self.type_(g);
        }
        let name = self.pop_if(is_decl_name);
        let ctx = self.pop_context();
        if labels.is_some() {
            self.with(K::Function, &[ctx, name, labels, t])
        } else {
            self.with(K::Function, &[ctx, name, t])
        }
    }

    fn pop_function_type(&mut self, kind: Kind, clang_type: bool) -> N {
        let fun = self.node(kind);
        if clang_type {
            let ct = self.clang_type()?;
            self.push_child(fun, ct);
        }
        let p = self.pop_kind(K::GlobalActorFunctionType);
        self.add_if(fun, p);
        let p = self.pop_kind(K::IsolatedAnyFunctionType);
        self.add_if(fun, p);
        let p = self.pop_kind(K::NonIsolatedCallerFunctionType);
        self.add_if(fun, p);
        let p = self.pop_kind(K::SendingResultFunctionType);
        self.add_if(fun, p);
        let p = self.pop_if(|k| k == K::ThrowsAnnotation || k == K::TypedThrowsAnnotation);
        self.add_if(fun, p);
        let p = self.pop_kind(K::ConcurrentFunctionType);
        self.add_if(fun, p);
        let p = self.pop_kind(K::DifferentiableFunctionType);
        self.add_if(fun, p);
        let p = self.pop_kind(K::AsyncAnnotation);
        self.add_if(fun, p);
        let args = self.pop_function_params(K::ArgumentTuple);
        let out = self.add(Some(fun), args);
        let ret = self.pop_function_params(K::ReturnType);
        let out = self.add(out, ret);
        self.type_(out)
    }

    fn clang_type(&mut self) -> N {
        let length = self.natural();
        if length < 0 || self.pos + length as usize > self.s.len() {
            return None;
        }
        let at = self.t.texts.len();
        self.u.push_text(&mut self.t.texts, self.pos, self.pos + length as usize);
        self.pos += length as usize;
        Some(self.make_since(K::ClangType, at))
    }

    fn pop_function_params(&mut self, kind: Kind) -> N {
        let params = if self.pop_kind(K::EmptyList).is_some() {
            let tuple = self.node(K::Tuple);
            self.type_(Some(tuple))
        } else {
            self.pop_kind(K::Type)
        }?;
        let n = if kind == K::ArgumentTuple {
            let first = self.first(params);
            let index = if self.kind(first) == K::Tuple { self.count(first) as i64 } else { 1 };
            self.node_index(kind, index)
        } else {
            self.node(kind)
        };
        self.push_child(n, params);
        Some(n)
    }

    fn pop_function_param_labels(&mut self, t: N) -> N {
        if self.pop_kind(K::EmptyList).is_some() {
            return Some(self.node(K::LabelList));
        }
        let t = t?;
        if self.kind(t) != K::Type {
            return None;
        }
        let mut fun = self.first(t);
        if self.kind(fun) == K::DependentGenericType {
            let c = self.child(fun, 1);
            fun = self.first(c);
        }
        if self.kind(fun) != K::FunctionType && self.kind(fun) != K::NoEscapeFunctionType {
            return None;
        }
        let args = self.t.children(fun).iter().copied().find(|&c| self.kind(c) == K::ArgumentTuple)?;
        let a = self.first(args);
        let params = self.first(a);
        let count = if self.kind(params) == K::Tuple { self.count(params) } else { 1 };
        if count == 0 {
            return None;
        }
        let labels = self.node(K::LabelList);
        let mut any = false;
        for _ in 0..count {
            let label = self.pop()?;
            let k = self.kind(label);
            if k != K::Identifier && k != K::FirstElementMarker {
                return None;
            }
            self.push_child(labels, label);
            any |= k != K::FirstElementMarker;
        }
        if !any {
            return Some(self.node(K::LabelList));
        }
        self.reverse_children(labels);
        Some(labels)
    }

    fn pop_tuple(&mut self) -> N {
        let root = self.node(K::Tuple);
        if self.pop_kind(K::EmptyList).is_none() {
            loop {
                let first = self.pop_kind(K::FirstElementMarker).is_some();
                let element = self.node(K::TupleElement);
                let variadic = self.pop_kind(K::VariadicMarker);
                self.add_if(element, variadic);
                if let Some(ident) = self.pop_kind(K::Identifier) {
                    let (at, len) = (self.t.nodes[ident as usize].text_at, self.t.nodes[ident as usize].text_len);
                    let name = self.make_at(K::TupleElementName, at as usize, len, None);
                    self.push_child(element, name);
                }
                let t = self.pop_kind(K::Type)?;
                self.push_child(element, t);
                self.push_child(root, element);
                if first {
                    break;
                }
            }
            self.reverse_children(root);
        }
        self.type_(Some(root))
    }

    fn pop_type_list(&mut self) -> N {
        let root = self.node(K::TypeList);
        if self.pop_kind(K::EmptyList).is_none() {
            loop {
                let first = self.pop_kind(K::FirstElementMarker).is_some();
                let t = self.pop_kind(K::Type)?;
                self.push_child(root, t);
                if first {
                    break;
                }
            }
            self.reverse_children(root);
        }
        Some(root)
    }

    fn pop_protocol(&mut self) -> N {
        if let Some(t) = self.pop_kind(K::Type) {
            if self.count(t) < 1 || !self.is_protocol_node(t) {
                return None;
            }
            return Some(t);
        }
        let reference = self.pop_kind(K::ProtocolSymbolicReference).or_else(|| self.pop_kind(K::ObjectiveCProtocolSymbolicReference));
        if reference.is_some() {
            return reference;
        }
        let name = self.pop_if(is_decl_name);
        let ctx = self.pop_context();
        let p = self.with(K::Protocol, &[ctx, name]);
        self.type_(p)
    }

    fn protocol_list(&mut self) -> N {
        let list = self.node(K::TypeList);
        let protocols = self.with(K::ProtocolList, &[Some(list)]);
        if self.pop_kind(K::EmptyList).is_none() {
            loop {
                let first = self.pop_kind(K::FirstElementMarker).is_some();
                let p = self.pop_protocol()?;
                self.push_child(list, p);
                if first {
                    break;
                }
            }
            self.reverse_children(list);
        }
        protocols
    }

    /// The lists of generic arguments, innermost last; false when they end badly.
    fn bound_generics(&mut self, lists: &mut Vec<NodeId>) -> (bool, N) {
        let retro = self.pop_retroactive_conformances();
        loop {
            let list = self.node(K::TypeList);
            lists.push(list);
            while let Some(t) = self.pop_kind(K::Type) {
                self.push_child(list, t);
            }
            self.reverse_children(list);
            if self.pop_kind(K::EmptyList).is_some() {
                break;
            }
            if self.pop_kind(K::FirstElementMarker).is_none() {
                return (false, retro);
            }
        }
        (true, retro)
    }

    fn pop_retroactive_conformances(&mut self) -> N {
        let mut list: N = None;
        while let Some(c) = self.pop_kind(K::RetroactiveConformance) {
            let l = match list {
                Some(l) => l,
                None => {
                    let l = self.node(K::TypeList);
                    list = Some(l);
                    l
                }
            };
            self.push_child(l, c);
        }
        if let Some(l) = list {
            self.reverse_children(l);
        }
        list
    }

    fn bound_generic_type(&mut self) -> N {
        let mut lists = Vec::new();
        let (ok, retro) = self.bound_generics(&mut lists);
        if !ok {
            return None;
        }
        let nominal = self.pop_any_generic();
        let bound = self.bound_generic_args(nominal, &lists, 0)?;
        if let Some(retro) = retro {
            self.push_child(bound, retro);
        }
        let t = self.type_(Some(bound));
        self.add_sub(t);
        t
    }

    fn bound_generic_args(&mut self, nominal: N, lists: &[NodeId], at: usize) -> N {
        self.nesting += 1;
        if self.nesting > MAX_GENERIC_NESTING {
            self.bad = true;
            return None;
        }
        let out = self.bound_generic_args_body(nominal, lists, at);
        self.nesting -= 1;
        out
    }

    fn bound_generic_args_body(&mut self, nominal: N, lists: &[NodeId], mut at: usize) -> N {
        let mut nominal = nominal?;
        if at >= lists.len() {
            return None;
        }
        let kind = self.kind(nominal);
        if kind == K::TypeSymbolicReference || kind == K::ProtocolSymbolicReference {
            let remaining = self.node(K::TypeList);
            for i in (at..lists.len()).rev() {
                let children = self.children_of(lists[i]);
                self.extend_children(remaining, &children);
            }
            let t = self.type_(Some(nominal));
            return self.with(K::BoundGenericOtherNominalType, &[t, Some(remaining)]);
        }
        if self.count(nominal) == 0 {
            return None;
        }
        let ctx = self.first(nominal);
        let consumes = !matches!(
            kind,
            K::Variable
                | K::Subscript
                | K::ImplicitClosure
                | K::ExplicitClosure
                | K::DefaultArgumentInitializer
                | K::Initializer
                | K::PropertyWrapperBackingInitializer
                | K::PropertyWrapperInitFromProjectedValue
                | K::PropertyWrappedFieldInitAccessor
                | K::Static
        );
        let args = lists[at];
        if consumes {
            at += 1;
        }
        if at < lists.len() {
            let parent = if self.kind(ctx) == K::Extension {
                let inner = self.t.children(ctx).get(1).copied();
                let parent = self.bound_generic_args(inner, lists, at);
                let first = self.first(ctx);
                let parent = self.with(K::Extension, &[Some(first), parent]);
                if let Some(p) = parent {
                    if self.count(ctx) == 3 {
                        let c = self.child(ctx, 2);
                        self.push_child(p, c);
                    }
                }
                parent
            } else {
                self.bound_generic_args(Some(ctx), lists, at)
            };
            let rebuilt = self.with(kind, &[parent])?;
            let rest: Vec<NodeId> = self.t.children(nominal)[1..].to_vec();
            self.extend_children(rebuilt, &rest);
            nominal = rebuilt;
        }
        if !consumes || self.count(args) == 0 {
            return Some(nominal);
        }
        let kind = self.kind(nominal);
        if kind == K::Function || kind == K::Constructor {
            return self.with(K::BoundGenericFunction, &[Some(nominal), Some(args)]);
        }
        let bound = match kind {
            K::Class => K::BoundGenericClass,
            K::Structure => K::BoundGenericStructure,
            K::Enum => K::BoundGenericEnum,
            K::Protocol => K::BoundGenericProtocol,
            K::OtherNominalType => K::BoundGenericOtherNominalType,
            K::TypeAlias => K::BoundGenericTypeAlias,
            _ => return None,
        };
        let t = self.type_(Some(nominal));
        self.with(bound, &[t, Some(args)])
    }

    fn generic_signature(&mut self, counts: bool) -> N {
        let sig = self.node(K::DependentGenericSignature);
        if counts {
            while !self.next_if(b"l") {
                let mut count = 0;
                if !self.next_if(b"z") {
                    count = self.index() + 1;
                }
                if count < 0 || self.pos > self.s.len() {
                    return None;
                }
                let c = self.node_index(K::DependentGenericParamCount, count);
                self.push_child(sig, c);
            }
        } else {
            let c = self.node_index(K::DependentGenericParamCount, 1);
            self.push_child(sig, c);
        }
        let mut reqs = Vec::new();
        while let Some(r) = self.pop_if(is_requirement) {
            reqs.push(r);
        }
        reqs.reverse();
        self.extend_children(sig, &reqs);
        Some(sig)
    }

    fn generic_param(&mut self, depth: i64, index: i64) -> N {
        if depth < 0 || index < 0 {
            return None;
        }
        let n = self.node(K::DependentGenericParamType);
        let d = self.node_index(K::Index, depth);
        let i = self.node_index(K::Index, index);
        self.extend_children(n, &[d, i]);
        Some(n)
    }

    fn generic_param_index(&mut self) -> N {
        if self.next_if(b"d") {
            let depth = self.index() + 1;
            let index = self.index();
            return self.generic_param(depth, index);
        }
        if self.next_if(b"z") {
            return self.generic_param(0, 0);
        }
        if self.next_if(b"s") {
            return Some(self.node(K::ConstrainedExistentialSelf));
        }
        let index = self.index() + 1;
        self.generic_param(0, index)
    }

    fn generic_requirement(&mut self) -> N {
        #[derive(Clone, Copy, PartialEq)]
        enum TypeKind {
            Generic,
            Assoc,
            Compound,
            Substitution,
        }
        #[derive(Clone, Copy, PartialEq)]
        enum Constraint {
            Protocol,
            BaseClass,
            SameType,
            SameShape,
            Layout,
            PackMarker,
            Inverse,
            ValueMarker,
        }
        use Constraint as C;
        use TypeKind as T;
        let entry = match self.next() {
            b'v' => (C::PackMarker, T::Generic),
            b'V' => (C::ValueMarker, T::Generic),
            b'c' => (C::BaseClass, T::Assoc),
            b'C' => (C::BaseClass, T::Compound),
            b'b' => (C::BaseClass, T::Generic),
            b'B' => (C::BaseClass, T::Substitution),
            b't' => (C::SameType, T::Assoc),
            b'T' => (C::SameType, T::Compound),
            b's' => (C::SameType, T::Generic),
            b'S' => (C::SameType, T::Substitution),
            b'm' => (C::Layout, T::Assoc),
            b'M' => (C::Layout, T::Compound),
            b'l' => (C::Layout, T::Generic),
            b'L' => (C::Layout, T::Substitution),
            b'p' => (C::Protocol, T::Assoc),
            b'P' => (C::Protocol, T::Compound),
            b'Q' => (C::Protocol, T::Substitution),
            b'h' => (C::SameShape, T::Generic),
            b'i' => (C::Inverse, T::Generic),
            b'I' => (C::Inverse, T::Substitution),
            _ => {
                self.back();
                (C::Protocol, T::Generic)
            }
        };
        let (constraint, type_kind) = entry;
        // An inverse requirement (~Copyable) names the protocol before the type.
        let inverse = if constraint == C::Inverse { self.index() } else { 0 };
        let t = match type_kind {
            T::Generic => {
                let p = self.generic_param_index();
                self.type_(p)
            }
            T::Assoc => {
                let p = self.generic_param_index();
                let t = self.associated_type_simple(p);
                self.add_sub(t);
                t
            }
            T::Compound => {
                let p = self.generic_param_index();
                let t = self.associated_type_compound(p);
                self.add_sub(t);
                t
            }
            T::Substitution => self.pop_kind(K::Type),
        };
        match constraint {
            C::ValueMarker => {
                let v = self.pop_kind(K::Type);
                self.with(K::DependentGenericParamValueMarker, &[t, v])
            }
            C::PackMarker => self.with(K::DependentGenericParamPackMarker, &[t]),
            C::Protocol => {
                let p = self.pop_protocol();
                self.with(K::DependentGenericConformanceRequirement, &[t, p])
            }
            C::Inverse => {
                if inverse < 0 {
                    return None;
                }
                let i = self.node_index(K::Index, inverse);
                self.with(K::DependentGenericInverseConformanceRequirement, &[t, Some(i)])
            }
            C::BaseClass => {
                let b = self.pop_kind(K::Type);
                self.with(K::DependentGenericConformanceRequirement, &[t, b])
            }
            C::SameType => {
                let b = self.pop_kind(K::Type);
                self.with(K::DependentGenericSameTypeRequirement, &[t, b])
            }
            C::SameShape => {
                let b = self.pop_kind(K::Type);
                self.with(K::DependentGenericSameShapeRequirement, &[t, b])
            }
            C::Layout => {
                let c = self.next();
                let mut size: N = None;
                let mut alignment: N = None;
                if c == b'E' || c == b'M' {
                    size = Some(self.index_node()?);
                    alignment = self.index_node();
                } else if c == b'e' || c == b'm' || c == b'S' {
                    size = Some(self.index_node()?);
                } else if c == 0 || !b"URNCDTB".contains(&c) {
                    return None;
                }
                let ident = self.node_char(K::Identifier, c);
                let req = self.with(K::DependentGenericLayoutRequirement, &[t, Some(ident)]);
                if let Some(r) = req {
                    self.add_if(r, size);
                    self.add_if(r, alignment);
                }
                req
            }
        }
    }

    fn associated_type_simple(&mut self, base: N) -> N {
        let name = self.pop_assoc_type_name();
        let base_type = if base.is_some() { self.type_(base) } else { self.pop_kind(K::Type) };
        let member = self.with(K::DependentMemberType, &[base_type, name]);
        self.type_(member)
    }

    fn associated_type_compound(&mut self, base: N) -> N {
        let mut names = Vec::new();
        loop {
            let first = self.pop_kind(K::FirstElementMarker).is_some();
            let name = self.pop_assoc_type_name()?;
            names.push(name);
            if first {
                break;
            }
        }
        let mut base_type = if base.is_some() { self.type_(base) } else { self.pop_kind(K::Type) };
        while let Some(name) = names.pop() {
            let member = self.with(K::DependentMemberType, &[base_type, Some(name)]);
            base_type = self.type_(member);
        }
        base_type
    }

    fn pop_assoc_type_name(&mut self) -> N {
        let mut proto = self.pop_kind(K::Type);
        if let Some(p) = proto {
            if !self.is_protocol_node(p) {
                return None;
            }
        }
        if proto.is_none() {
            proto = self.pop_kind(K::ProtocolSymbolicReference).or_else(|| self.pop_kind(K::ObjectiveCProtocolSymbolicReference));
        }
        let id = self.pop_kind(K::Identifier);
        let reference = self.with(K::DependentAssociatedTypeRef, &[id]);
        if let (Some(r), Some(p)) = (reference, proto) {
            self.push_child(r, p);
        }
        reference
    }

    fn pop_assoc_type_path(&mut self) -> N {
        let path = self.node(K::AssocTypePath);
        loop {
            let first = self.pop_kind(K::FirstElementMarker).is_some();
            let t = self.pop_assoc_type_name()?;
            self.push_child(path, t);
            if first {
                break;
            }
        }
        self.reverse_children(path);
        Some(path)
    }

    fn generic_type(&mut self) -> N {
        let sig = self.pop_kind(K::DependentGenericSignature);
        let t = self.pop_kind(K::Type);
        let g = self.with(K::DependentGenericType, &[sig, t]);
        self.type_(g)
    }

    fn archetype(&mut self) -> N {
        match self.next() {
            b'a' => {
                let ident = self.pop_kind(K::Identifier);
                let base = self.pop_type_child();
                let r = self.with(K::AssociatedTypeRef, &[base, ident]);
                let t = self.type_(r);
                self.add_sub(t);
                t
            }
            b'O' => {
                let ctx = self.pop_context();
                self.with(K::OpaqueReturnTypeOf, &[ctx])
            }
            b'o' => {
                let index = self.index();
                let mut lists = Vec::new();
                let (ok, retro) = self.bound_generics(&mut lists);
                if !ok {
                    return None;
                }
                let name = self.pop()?;
                if index < 0 {
                    return None;
                }
                let i = self.node_index(K::Index, index);
                let opaque = self.with(K::OpaqueType, &[Some(name), Some(i)]).unwrap();
                let bound = self.node(K::TypeList);
                for &list in lists.iter().rev() {
                    self.push_child(bound, list);
                }
                self.push_child(opaque, bound);
                self.add_if(opaque, retro);
                let t = self.type_(Some(opaque));
                self.add_sub(t);
                t
            }
            b'r' => {
                let r = self.node(K::OpaqueReturnType);
                self.type_(Some(r))
            }
            b'R' => {
                let ordinal = self.index();
                if ordinal < 0 {
                    return None;
                }
                let i = self.node_index(K::OpaqueReturnTypeIndex, ordinal);
                let r = self.with(K::OpaqueReturnType, &[Some(i)]);
                self.type_(r)
            }
            b'x' => {
                let t = self.associated_type_simple(None);
                self.add_sub(t);
                t
            }
            b'X' => {
                let t = self.associated_type_compound(None);
                self.add_sub(t);
                t
            }
            b'y' => {
                let p = self.generic_param_index();
                let t = self.associated_type_simple(p);
                self.add_sub(t);
                t
            }
            b'Y' => {
                let p = self.generic_param_index();
                let t = self.associated_type_compound(p);
                self.add_sub(t);
                t
            }
            b'z' => {
                let p = self.generic_param(0, 0);
                let t = self.associated_type_simple(p);
                self.add_sub(t);
                t
            }
            b'Z' => {
                let p = self.generic_param(0, 0);
                let t = self.associated_type_compound(p);
                self.add_sub(t);
                t
            }
            b'p' => {
                let count = self.pop_type_child();
                let pattern = self.pop_type_child();
                let e = self.with(K::PackExpansion, &[pattern, count]);
                self.type_(e)
            }
            b'e' => {
                let pack = self.pop_type_child();
                let level = self.index();
                if level < 0 {
                    return None;
                }
                let l = self.node_index(K::PackElementLevel, level);
                let e = self.with(K::PackElement, &[pack, Some(l)]);
                self.type_(e)
            }
            b'P' => {
                let list = self.pop_type_list()?;
                let pack = self.change_kind(Some(list), K::Pack);
                self.type_(pack)
            }
            _ => None,
        }
    }

    fn metatype(&mut self) -> N {
        let kind = match self.next() {
            b'a' => K::TypeMetadataAccessFunction,
            b'A' => {
                let c = self.pop_conformance();
                return self.with(K::ReflectionMetadataAssocTypeDescriptor, &[c]);
            }
            b'b' => K::CanonicalSpecializedGenericTypeMetadataAccessFunction,
            b'B' => K::ReflectionMetadataBuiltinDescriptor,
            b'c' => {
                let c = self.pop_conformance();
                return self.with(K::ProtocolConformanceDescriptor, &[c]);
            }
            b'C' => {
                let t = self.pop_kind(K::Type)?;
                let first = self.first(t);
                if !is_any_generic(self.kind(first)) {
                    return None;
                }
                return self.with(K::ReflectionMetadataSuperclassDescriptor, &[Some(first)]);
            }
            b'D' | b'd' => K::TypeMetadataDemanglingCache,
            b'f' => K::FullTypeMetadata,
            b'F' => K::ReflectionMetadataFieldDescriptor,
            b'g' => return self.with_popped(K::OpaqueTypeDescriptorAccessor),
            b'h' => return self.with_popped(K::OpaqueTypeDescriptorAccessorImpl),
            b'i' => K::TypeMetadataInstantiationFunction,
            b'I' => K::TypeMetadataInstantiationCache,
            b'j' => return self.with_popped(K::OpaqueTypeDescriptorAccessorKey),
            b'J' => return self.with_popped(K::NoncanonicalSpecializedGenericTypeMetadataCache),
            b'k' => return self.with_popped(K::OpaqueTypeDescriptorAccessorVar),
            b'K' => return self.with_popped(K::MetadataInstantiationCache),
            b'l' => K::TypeMetadataSingletonInitializationCache,
            b'L' => K::TypeMetadataLazyCache,
            b'm' => K::Metaclass,
            b'M' => K::CanonicalSpecializedGenericMetaclass,
            b'n' => K::NominalTypeDescriptor,
            b'N' => K::NoncanonicalSpecializedGenericTypeMetadata,
            b'o' => K::ClassMetadataBaseOffset,
            b'p' => {
                let p = self.pop_protocol();
                return self.with(K::ProtocolDescriptor, &[p]);
            }
            b'P' => K::GenericTypeMetadataPattern,
            b'q' => return self.with_popped(K::Uniquable),
            b'Q' => return self.with_popped(K::OpaqueTypeDescriptor),
            b'r' => K::TypeMetadataCompletionFunction,
            b'R' => K::TypeMetadataMangledNameRef,
            b's' => K::ObjCResilientClassStub,
            b'S' => {
                let p = self.pop_protocol();
                return self.with(K::ProtocolSelfConformanceDescriptor, &[p]);
            }
            b't' => K::FullObjCResilientClassStub,
            b'u' => K::MethodLookupFunction,
            b'U' => K::ObjCMetadataUpdateFunction,
            b'V' => {
                let e = self.pop_entity();
                return self.with(K::PropertyDescriptor, &[e]);
            }
            b'X' => return self.private_context_descriptor(),
            b'z' => K::CanonicalPrespecializedGenericTypeCachingOnceToken,
            _ => return None,
        };
        let t = self.pop_kind(K::Type);
        self.with(kind, &[t])
    }

    /// A node of the kind over whatever is on top of the stack.
    fn with_popped(&mut self, kind: Kind) -> N {
        let n = self.pop();
        self.with(kind, &[n])
    }

    fn private_context_descriptor(&mut self) -> N {
        match self.next() {
            b'E' => {
                let ctx = self.pop_context();
                self.with(K::ExtensionDescriptor, &[ctx])
            }
            b'M' => {
                let module = self.pop_module();
                self.with(K::ModuleDescriptor, &[module])
            }
            b'Y' => {
                let discriminator = self.pop();
                let ctx = self.pop_context();
                self.with(K::AnonymousDescriptor, &[ctx, discriminator])
            }
            b'X' => {
                let ctx = self.pop_context();
                self.with(K::AnonymousDescriptor, &[ctx])
            }
            b'A' => {
                let path = self.pop_assoc_type_path();
                let base = self.pop_kind(K::Type);
                self.with(K::AssociatedTypeGenericParamRef, &[base, path])
            }
            _ => None,
        }
    }

    fn pop_conformance(&mut self) -> N {
        let sig = self.pop_kind(K::DependentGenericSignature);
        let module = self.pop_module();
        let proto = self.pop_protocol();
        let mut t = self.pop_kind(K::Type);
        let mut ident: N = None;
        if t.is_none() {
            ident = self.pop_kind(K::Identifier);
            t = self.pop_kind(K::Type);
        }
        if sig.is_some() {
            let g = self.with(K::DependentGenericType, &[sig, t]);
            t = self.type_(g);
        }
        let conf = self.with(K::ProtocolConformance, &[t, proto, module]);
        if let Some(c) = conf {
            self.add_if(c, ident);
        }
        conf
    }

    fn pop_any_conformance_list(&mut self) -> N {
        let list = self.node(K::AnyProtocolConformanceList);
        if self.pop_kind(K::EmptyList).is_none() {
            loop {
                let first = self.pop_kind(K::FirstElementMarker).is_some();
                let c = self.pop_if(is_any_conformance)?;
                self.push_child(list, c);
                if first {
                    break;
                }
            }
            self.reverse_children(list);
        }
        Some(list)
    }
    fn retroactive_conformance(&mut self) -> N {
        let index = self.index();
        if index < 0 {
            return None;
        }
        let conf = self.pop_if(is_any_conformance)?;
        let i = self.node_index(K::Index, index);
        self.with(K::RetroactiveConformance, &[Some(i), Some(conf)])
    }
    fn concrete_conformance(&mut self) -> N {
        let conditional = self.pop_any_conformance_list();
        let mut reference = self.pop_kind(K::ProtocolConformanceRefInTypeModule);
        if reference.is_none() {
            reference = self.pop_kind(K::ProtocolConformanceRefInProtocolModule);
        }
        if reference.is_none() {
            reference = self.conformance_ref();
        }
        let t = self.pop_kind(K::Type);
        self.with(K::ConcreteProtocolConformance, &[t, reference, conditional])
    }
    fn conformance_ref(&mut self) -> N {
        let module = self.pop_module();
        let proto = self.pop_protocol();
        self.with(K::ProtocolConformanceRefInOtherModule, &[proto, module])
    }
    fn dependent_conformance_index(&mut self) -> N {
        let index = self.index();
        if index <= 0 {
            return None;
        }
        if index == 1 {
            return Some(self.node(K::UnknownIndex));
        }
        Some(self.node_index(K::Index, index - 2))
    }
    fn dependent_conformance_root(&mut self) -> N {
        let index = self.dependent_conformance_index();
        let proto = self.pop_protocol();
        let t = self.pop_kind(K::Type);
        self.with(K::DependentProtocolConformanceRoot, &[t, proto, index])
    }
    fn dependent_conformance_inherited(&mut self) -> N {
        let index = self.dependent_conformance_index();
        let proto = self.pop_protocol();
        let nested = self.pop_if(is_dependent_conformance);
        self.with(K::DependentProtocolConformanceInherited, &[nested, proto, index])
    }
    fn dependent_conformance_associated(&mut self) -> N {
        let index = self.dependent_conformance_index();
        let proto = self.pop_protocol();
        let t = self.pop_kind(K::Type);
        let assoc = self.with(K::DependentAssociatedConformance, &[t, proto]);
        let nested = self.pop_if(is_dependent_conformance);
        self.with(K::DependentProtocolConformanceAssociated, &[nested, assoc, index])
    }

    fn witness(&mut self) -> N {
        let c = self.next();
        match c {
            b'C' => {
                let e = self.pop_entity();
                self.with(K::EnumCase, &[e])
            }
            b'V' => {
                let t = self.pop_kind(K::Type);
                self.with(K::ValueWitnessTable, &[t])
            }
            b'v' => {
                let d = self.next();
                if d != b'd' && d != b'i' {
                    return None;
                }
                let directness = self.node_index(K::Directness, if d == b'd' { 0 } else { 1 });
                let e = self.pop_entity();
                self.with(K::FieldOffset, &[Some(directness), e])
            }
            b'S' => {
                let p = self.pop_protocol();
                self.with(K::ProtocolSelfConformanceWitnessTable, &[p])
            }
            b'P' => self.with_conformance(K::ProtocolWitnessTable),
            b'p' => self.with_conformance(K::ProtocolWitnessTablePattern),
            b'G' => self.with_conformance(K::GenericProtocolWitnessTable),
            b'I' => self.with_conformance(K::GenericProtocolWitnessTableInstantiationFunction),
            b'r' => self.with_conformance(K::ResilientProtocolWitnessTable),
            b'l' | b'L' => {
                let conf = self.pop_conformance();
                let t = self.pop_kind(K::Type);
                self.with(if c == b'l' { K::LazyProtocolWitnessTableAccessor } else { K::LazyProtocolWitnessTableCacheVariable }, &[t, conf])
            }
            b'a' => self.with_conformance(K::ProtocolWitnessTableAccessor),
            b't' => {
                let name = self.pop_if(is_decl_name);
                let conf = self.pop_conformance();
                self.with(K::AssociatedTypeMetadataAccessor, &[conf, name])
            }
            b'T' => {
                let proto = self.pop_kind(K::Type);
                let path = self.pop_assoc_type_path();
                let conf = self.pop_conformance();
                self.with(K::AssociatedTypeWitnessTableAccessor, &[conf, path, proto])
            }
            b'b' => {
                let proto = self.pop_kind(K::Type);
                let conf = self.pop_conformance();
                self.with(K::BaseWitnessTableAccessor, &[conf, proto])
            }
            b'O' => {
                let o = self.next();
                let kind = match o {
                    b'B' => K::OutlinedInitializeWithTakeNoValueWitness,
                    b'C' => K::OutlinedInitializeWithCopyNoValueWitness,
                    b'D' => K::OutlinedAssignWithTakeNoValueWitness,
                    b'F' => K::OutlinedAssignWithCopyNoValueWitness,
                    b'H' => K::OutlinedDestroyNoValueWitness,
                    b'y' => K::OutlinedCopy,
                    b'e' => K::OutlinedConsume,
                    b'r' => K::OutlinedRetain,
                    b's' => K::OutlinedRelease,
                    b'b' => K::OutlinedInitializeWithTake,
                    b'c' => K::OutlinedInitializeWithCopy,
                    b'd' => K::OutlinedAssignWithTake,
                    b'f' => K::OutlinedAssignWithCopy,
                    b'h' => K::OutlinedDestroy,
                    b'g' => K::OutlinedEnumGetTag,
                    b'i' => K::OutlinedEnumTagStore,
                    b'j' => K::OutlinedEnumProjectDataForLoad,
                    _ => return None,
                };
                let sig = self.pop_kind(K::DependentGenericSignature);
                let t = self.pop_kind(K::Type);
                let n = self.with(kind, &[t]);
                if let Some(n) = n {
                    self.add_if(n, sig);
                }
                if o == b'i' || o == b'j' {
                    let index = self.index_node();
                    return self.add(n, index);
                }
                n
            }
            b'Z' | b'z' => {
                let list = self.node(K::GlobalVariableOnceDeclList);
                let mut vars = Vec::new();
                while self.pop_kind(K::FirstElementMarker).is_some() {
                    vars.push(self.pop_if(is_decl_name)?);
                }
                vars.reverse();
                self.extend_children(list, &vars);
                let ctx = self.pop_context();
                self.with(if c == b'Z' { K::GlobalVariableOnceFunction } else { K::GlobalVariableOnceToken }, &[ctx, Some(list)])
            }
            _ => None,
        }
    }

    fn with_conformance(&mut self, kind: Kind) -> N {
        let conf = self.pop_conformance();
        self.with(kind, &[conf])
    }

    fn special_type(&mut self) -> N {
        let c = self.next();
        match c {
            b'E' => self.pop_function_type(K::NoEscapeFunctionType, false),
            b'A' => self.pop_function_type(K::EscapingAutoClosureType, false),
            b'f' => self.pop_function_type(K::ThinFunctionType, false),
            b'K' => self.pop_function_type(K::AutoClosureType, false),
            b'U' => self.pop_function_type(K::UncurriedFunctionType, false),
            b'L' => self.pop_function_type(K::EscapingObjCBlock, false),
            b'B' => self.pop_function_type(K::ObjCBlock, false),
            b'C' => self.pop_function_type(K::CFunctionPointer, false),
            b'z' => match self.next() {
                b'B' => self.pop_function_type(K::ObjCBlock, true),
                b'C' => self.pop_function_type(K::CFunctionPointer, true),
                _ => None,
            },
            b'o' => self.type_over_popped(K::Unowned),
            b'u' => self.type_over_popped(K::Unmanaged),
            b'w' => self.type_over_popped(K::Weak),
            b'b' => self.type_over_popped(K::SILBoxType),
            b'D' => self.type_over_popped(K::DynamicSelf),
            b'M' | b'm' => {
                let repr = self.metatype_representation();
                let t = self.pop_kind(K::Type);
                let m = self.with(if c == b'M' { K::Metatype } else { K::ExistentialMetatype }, &[repr, t]);
                self.type_(m)
            }
            b'P' => {
                let reqs = self.constrained_existential_requirements();
                let base = self.pop_kind(K::Type);
                let e = self.with(K::ConstrainedExistential, &[base, reqs]);
                self.type_(e)
            }
            b'p' => self.type_over_popped(K::ExistentialMetatype),
            b'c' => {
                let superclass = self.pop_kind(K::Type);
                let protocols = self.protocol_list();
                let l = self.with(K::ProtocolListWithClass, &[protocols, superclass]);
                self.type_(l)
            }
            b'l' => {
                let protocols = self.protocol_list();
                let l = self.with(K::ProtocolListWithAnyObject, &[protocols]);
                self.type_(l)
            }
            b'X' | b'x' => {
                let mut sig: N = None;
                let mut args: N = None;
                if c == b'X' {
                    sig = Some(self.pop_kind(K::DependentGenericSignature)?);
                    args = Some(self.pop_type_list()?);
                }
                let fields = self.pop_type_list()?;
                let layout = self.node(K::SILBoxLayout);
                let fields: Vec<NodeId> = self.children_of(fields);
                for mut field in fields {
                    let mut mutable = false;
                    let first = self.first(field);
                    if self.kind(first) == K::InOut {
                        mutable = true;
                        let inner = self.first(first);
                        field = self.type_(Some(inner)).unwrap();
                    }
                    let f = self.node(if mutable { K::SILBoxMutableField } else { K::SILBoxImmutableField });
                    self.push_child(f, field);
                    self.push_child(layout, f);
                }
                let boxed = self.node(K::SILBoxTypeWithLayout);
                self.push_child(boxed, layout);
                if let (Some(sig), Some(args)) = (sig, args) {
                    self.push_child(boxed, sig);
                    self.push_child(boxed, args);
                }
                self.type_(Some(boxed))
            }
            b'Y' => self.any_generic_type(K::OtherNominalType),
            b'Z' => {
                let types = self.pop_type_list();
                let name = self.pop_kind(K::Identifier);
                let parent = self.pop_context();
                let anon = Some(self.node(K::AnonymousContext));
                let anon = self.add(anon, name);
                let anon = self.add(anon, parent);
                self.add(anon, types)
            }
            b'e' => {
                let e = self.node(K::ErrorType);
                self.type_(Some(e))
            }
            b'S' => match self.next() {
                b'q' => self.type_over_popped(K::SugaredOptional),
                b'a' => self.type_over_popped(K::SugaredArray),
                b'D' => {
                    let value = self.pop_kind(K::Type);
                    let key = self.pop_kind(K::Type);
                    let d = self.with(K::SugaredDictionary, &[key, value]);
                    self.type_(d)
                }
                b'p' => self.type_over_popped(K::SugaredParen),
                _ => None,
            },
            _ => None,
        }
    }

    /// A type of the kind over the type on top of the stack.
    fn type_over_popped(&mut self, kind: Kind) -> N {
        let t = self.pop_kind(K::Type);
        let n = self.with(kind, &[t]);
        self.type_(n)
    }

    fn metatype_representation(&mut self) -> N {
        let text = match self.next() {
            b't' => "@thin",
            b'T' => "@thick",
            b'o' => "@objc_metatype",
            _ => return None,
        };
        Some(self.node_text(K::MetatypeRepresentation, text))
    }

    fn constrained_existential_requirements(&mut self) -> N {
        let list = self.node(K::ConstrainedExistentialRequirementList);
        loop {
            let first = self.pop_kind(K::FirstElementMarker).is_some();
            let r = self.pop_if(is_requirement)?;
            self.push_child(list, r);
            if first {
                break;
            }
        }
        self.reverse_children(list);
        Some(list)
    }

    fn type_annotation(&mut self) -> N {
        match self.next() {
            b'a' => Some(self.node(K::AsyncAnnotation)),
            b'A' => Some(self.node(K::IsolatedAnyFunctionType)),
            b'b' => Some(self.node(K::ConcurrentFunctionType)),
            b'c' => {
                let c = self.pop_type_child();
                self.with(K::GlobalActorFunctionType, &[c])
            }
            b'C' => Some(self.node(K::NonIsolatedCallerFunctionType)),
            b'i' => self.type_over_type_child(K::Isolated),
            b'k' => self.type_over_type_child(K::NoDerivative),
            b'K' => {
                let c = self.pop_type_child();
                self.with(K::TypedThrowsAnnotation, &[c])
            }
            b't' => self.type_over_type_child(K::CompileTimeLiteral),
            b'g' => self.type_over_type_child(K::ConstValue),
            b'T' => Some(self.node(K::SendingResultFunctionType)),
            b'u' => self.type_over_type_child(K::Sending),
            b'j' => {
                let k = self.next();
                if !b"dlfr".contains(&k) {
                    return None;
                }
                Some(self.node_index(K::DifferentiableFunctionType, k as i64))
            }
            _ => None,
        }
    }

    /// A type of the kind over the child of the type on top of the stack.
    fn type_over_type_child(&mut self, kind: Kind) -> N {
        let c = self.pop_type_child();
        let n = self.with(kind, &[c]);
        self.type_(n)
    }

    fn function_entity(&mut self) -> N {
        #[derive(Clone, Copy, PartialEq)]
        enum Args {
            None,
            TypeAndName,
            TypeAndIndex,
            Index,
        }
        let (args, kind) = match self.next() {
            b'D' => (Args::None, K::Deallocator),
            b'd' => (Args::None, K::Destructor),
            b'Z' => (Args::None, K::IsolatedDeallocator),
            b'E' => (Args::None, K::IVarDestroyer),
            b'e' => (Args::None, K::IVarInitializer),
            b'i' => (Args::None, K::Initializer),
            b'C' => (Args::TypeAndName, K::Allocator),
            b'c' => (Args::TypeAndName, K::Constructor),
            b'U' => (Args::TypeAndIndex, K::ExplicitClosure),
            b'u' => (Args::TypeAndIndex, K::ImplicitClosure),
            b'A' => (Args::Index, K::DefaultArgumentInitializer),
            b'm' => return self.entity(K::Macro),
            b'M' => return self.macro_expansion(),
            b'p' => return self.entity(K::GenericTypeParamDecl),
            b'P' => (Args::None, K::PropertyWrapperBackingInitializer),
            b'W' => (Args::None, K::PropertyWrapperInitFromProjectedValue),
            b'F' => (Args::None, K::PropertyWrappedFieldInitAccessor),
            _ => return None,
        };
        let mut name_or_index: N = None;
        let mut param_type: N = None;
        let mut labels: N = None;
        match args {
            Args::TypeAndName => {
                name_or_index = self.pop_kind(K::PrivateDeclName);
                param_type = self.pop_kind(K::Type);
                labels = self.pop_function_param_labels(param_type);
            }
            Args::TypeAndIndex => {
                name_or_index = self.index_node();
                param_type = self.pop_kind(K::Type);
            }
            Args::Index => name_or_index = self.index_node(),
            Args::None => {}
        }
        let ctx = self.pop_context();
        let mut entity = self.with(kind, &[ctx]);
        match args {
            Args::Index => entity = self.add(entity, name_or_index),
            Args::TypeAndName => {
                if let Some(e) = entity {
                    self.add_if(e, labels);
                }
                entity = self.add(entity, param_type);
                if let Some(e) = entity {
                    self.add_if(e, name_or_index);
                }
            }
            Args::TypeAndIndex => {
                entity = self.add(entity, name_or_index);
                entity = self.add(entity, param_type);
            }
            Args::None => {}
        }
        entity
    }

    fn entity(&mut self, kind: Kind) -> N {
        let t = self.pop_kind(K::Type);
        let labels = self.pop_function_param_labels(t);
        let name = self.pop_if(is_decl_name);
        let ctx = self.pop_context();
        if labels.is_some() {
            self.with(kind, &[ctx, name, labels, t])
        } else {
            self.with(kind, &[ctx, name, t])
        }
    }

    fn variable(&mut self) -> N {
        let v = self.entity(K::Variable);
        self.accessor(v)
    }

    fn subscript(&mut self) -> N {
        let private_name = self.pop_kind(K::PrivateDeclName);
        let t = self.pop_kind(K::Type);
        let labels = self.pop_function_param_labels(t);
        let ctx = self.pop_context();
        let sub = Some(self.node(K::Subscript));
        let mut sub = self.add(sub, ctx);
        if let Some(s) = sub {
            self.add_if(s, labels);
        }
        sub = self.add(sub, t);
        if let Some(s) = sub {
            self.add_if(s, private_name);
        }
        self.accessor(sub)
    }

    fn accessor(&mut self, child: N) -> N {
        let kind = match self.next() {
            b'm' => K::MaterializeForSet,
            b's' => K::Setter,
            b'g' => K::Getter,
            b'G' => K::GlobalGetter,
            b'w' => K::WillSet,
            b'W' => K::DidSet,
            b'r' => K::ReadAccessor,
            b'y' => K::Read2Accessor,
            b'M' => K::ModifyAccessor,
            b'x' => K::Modify2Accessor,
            b'i' => K::InitAccessor,
            b'a' => match self.next() {
                b'O' => K::OwningMutableAddressor,
                b'o' => K::NativeOwningMutableAddressor,
                b'P' => K::NativePinningMutableAddressor,
                b'u' => K::UnsafeMutableAddressor,
                _ => return None,
            },
            b'l' => match self.next() {
                b'O' => K::OwningAddressor,
                b'o' => K::NativeOwningAddressor,
                b'p' => K::NativePinningAddressor,
                b'u' => K::UnsafeAddressor,
                _ => return None,
            },
            b'p' => return child,
            _ => return None,
        };
        self.with(kind, &[child])
    }

    fn macro_expansion(&mut self) -> N {
        let (kind, attached, freestanding) = match self.next() {
            b'a' => (K::AccessorAttachedMacroExpansion, true, false),
            b'r' => (K::MemberAttributeAttachedMacroExpansion, true, false),
            b'm' => (K::MemberAttachedMacroExpansion, true, false),
            b'p' => (K::PeerAttachedMacroExpansion, true, false),
            b'c' => (K::ConformanceAttachedMacroExpansion, true, false),
            b'e' => (K::ExtensionAttachedMacroExpansion, true, false),
            b'q' => (K::PreambleAttachedMacroExpansion, true, false),
            b'b' => (K::BodyAttachedMacroExpansion, true, false),
            b'f' => (K::FreestandingMacroExpansion, false, true),
            b'u' => (K::MacroExpansionUniqueName, false, false),
            _ => return None,
        };
        let macro_name = self.pop_kind(K::Identifier);
        let private_discriminator = if freestanding { self.pop_kind(K::PrivateDeclName) } else { None };
        let attached_name = if attached { self.pop_if(is_decl_name) } else { None };
        let ctx = match self.pop_if(is_macro_expansion) {
            Some(c) => Some(c),
            None => self.pop_context(),
        };
        let discriminator = self.index_node();
        let result = if attached { self.with(kind, &[ctx, attached_name, macro_name, discriminator]) } else { self.with(kind, &[ctx, macro_name, discriminator]) };
        if let Some(r) = result {
            self.add_if(r, private_discriminator);
        }
        result
    }

    fn value_witness(&mut self) -> N {
        let a = self.next();
        let b = self.next();
        let name = value_witness(a, b)?;
        let vw = self.node(K::ValueWitness);
        let index = self.node_text(K::Index, name);
        self.push_child(vw, index);
        let t = self.pop_kind(K::Type);
        self.add(Some(vw), t)
    }

    fn thunk_or_specialization(&mut self) -> N {
        let c = self.next();
        match c {
            b'T' => match self.next() {
                b'I' => {
                    let e = self.pop_entity();
                    self.with(K::SILThunkIdentity, &[e])
                }
                b'H' => {
                    let e = self.pop_entity();
                    self.with(K::SILThunkHopToMainActorIfNeeded, &[e])
                }
                _ => None,
            },
            b'c' => {
                let e = self.pop_entity();
                self.with(K::CurryThunk, &[e])
            }
            b'j' => {
                let e = self.pop_entity();
                self.with(K::DispatchThunk, &[e])
            }
            b'q' => {
                let e = self.pop_entity();
                self.with(K::MethodDescriptor, &[e])
            }
            b'o' => Some(self.node(K::ObjCAttribute)),
            b'O' => Some(self.node(K::NonObjCAttribute)),
            b'D' => Some(self.node(K::DynamicAttribute)),
            b'd' => Some(self.node(K::DirectMethodReferenceAttribute)),
            b'E' => Some(self.node(K::DistributedThunk)),
            b'F' => Some(self.node(K::DistributedAccessor)),
            b'a' => Some(self.node(K::PartialApplyObjCForwarder)),
            b'A' => Some(self.node(K::PartialApplyForwarder)),
            b'm' => Some(self.node(K::MergedFunction)),
            b'X' => Some(self.node(K::DynamicallyReplaceableFunctionVar)),
            b'x' => Some(self.node(K::DynamicallyReplaceableFunctionKey)),
            b'I' => Some(self.node(K::DynamicallyReplaceableFunctionImpl)),
            b'Y' | b'Q' => {
                let index = self.index_node();
                self.with(if c == b'Q' { K::AsyncAwaitResumePartialFunction } else { K::AsyncSuspendResumePartialFunction }, &[index])
            }
            b'C' => {
                let t = self.pop_kind(K::Type);
                self.with(K::CoroutineContinuationPrototype, &[t])
            }
            b'z' | b'Z' => {
                let flag = self.index_node()?;
                let sig = self.pop_kind(K::DependentGenericSignature);
                let result = self.pop_kind(K::Type);
                let implementation = self.pop_kind(K::Type);
                let kind = if c == b'z' { K::ObjCAsyncCompletionHandlerImpl } else { K::PredefinedObjCAsyncCompletionHandlerImpl };
                let n = self.with(kind, &[implementation, result, Some(flag)]);
                if let Some(n) = n {
                    self.add_if(n, sig);
                }
                n
            }
            b'V' => {
                let base = self.pop_entity();
                let derived = self.pop_entity();
                self.with(K::VTableThunk, &[derived, base])
            }
            b'W' => {
                let entity = self.pop_entity();
                let conf = self.pop_conformance();
                self.with(K::ProtocolWitness, &[conf, entity])
            }
            b'S' => {
                let e = self.pop_entity();
                self.with(K::ProtocolSelfConformanceWitness, &[e])
            }
            b'R' | b'r' | b'y' => {
                let kind = match c {
                    b'R' => K::ReabstractionThunkHelper,
                    b'y' => K::ReabstractionThunkHelperWithSelf,
                    _ => K::ReabstractionThunk,
                };
                let thunk = self.node(kind);
                let sig = self.pop_kind(K::DependentGenericSignature);
                self.add_if(thunk, sig);
                if kind == K::ReabstractionThunkHelperWithSelf {
                    let t = self.pop_kind(K::Type);
                    self.add_if(thunk, t);
                }
                let t = self.pop_kind(K::Type);
                self.add_if(thunk, t);
                let t = self.pop_kind(K::Type);
                self.add_if(thunk, t);
                Some(thunk)
            }
            b'g' => self.generic_specialization(K::GenericSpecialization, Vec::new()),
            b'G' => self.generic_specialization(K::GenericSpecializationNotReAbstracted, Vec::new()),
            b'B' => self.generic_specialization(K::GenericSpecializationInResilienceDomain, Vec::new()),
            b's' => self.generic_specialization(K::GenericSpecializationPrespecialized, Vec::new()),
            b'i' => self.generic_specialization(K::InlinedGenericFunction, Vec::new()),
            b't' => self.generic_specialization_with_dropped_arguments(),
            b'p' | b'P' => {
                let spec = self.spec_attributes(if c == b'p' { K::GenericPartialSpecialization } else { K::GenericPartialSpecializationNotReAbstracted });
                let t = self.pop_kind(K::Type);
                let param = self.with(K::GenericSpecializationParam, &[t]);
                self.add(spec, param)
            }
            b'f' => self.function_specialization(),
            b'K' | b'k' => {
                let kind = if c == b'K' { K::KeyPathGetterThunkHelper } else { K::KeyPathSetterThunkHelper };
                let serialized = self.next_if(b"q");
                let mut types = Vec::new();
                let mut n = self.pop()?;
                if self.kind(n) != K::Type {
                    return None;
                }
                let n = loop {
                    types.push(n);
                    match self.pop() {
                        Some(m) if self.kind(m) == K::Type => n = m,
                        Some(m) => break m,
                        None => return None,
                    }
                };
                let result = if self.kind(n) == K::DependentGenericSignature {
                    let decl = self.pop()?;
                    self.with(kind, &[Some(decl), Some(n)])
                } else {
                    self.with(kind, &[Some(n)])
                }
                .unwrap();
                types.reverse();
                self.extend_children(result, &types);
                if serialized {
                    let s = self.node(K::IsSerialized);
                    self.push_child(result, s);
                }
                Some(result)
            }
            b'l' => {
                let name = self.pop_assoc_type_name();
                self.with(K::AssociatedTypeDescriptor, &[name])
            }
            b'L' => {
                let p = self.pop_protocol();
                self.with(K::ProtocolRequirementsBaseDescriptor, &[p])
            }
            b'M' => {
                let name = self.pop_assoc_type_name();
                self.with(K::DefaultAssociatedTypeMetadataAccessor, &[name])
            }
            b'n' | b'N' => {
                let requirement = self.pop_protocol();
                let path = self.pop_assoc_type_path();
                let proto = self.pop_kind(K::Type);
                self.with(if c == b'n' { K::AssociatedConformanceDescriptor } else { K::DefaultAssociatedConformanceAccessor }, &[proto, path, requirement])
            }
            b'b' => {
                let requirement = self.pop_protocol();
                let proto = self.pop_kind(K::Type);
                self.with(K::BaseConformanceDescriptor, &[proto, requirement])
            }
            b'H' | b'h' => {
                let kind = if c == b'H' { K::KeyPathEqualsThunkHelper } else { K::KeyPathHashThunkHelper };
                let serialized = self.next_if(b"q");
                let mut sig: N = None;
                let mut types = Vec::new();
                let n = self.pop()?;
                match self.kind(n) {
                    K::DependentGenericSignature => sig = Some(n),
                    K::Type => types.push(n),
                    _ => return None,
                }
                while let Some(t) = self.pop() {
                    if self.kind(t) != K::Type {
                        return None;
                    }
                    types.push(t);
                }
                let result = self.node(kind);
                types.reverse();
                self.extend_children(result, &types);
                self.add_if(result, sig);
                if serialized {
                    let s = self.node(K::IsSerialized);
                    self.push_child(result, s);
                }
                Some(result)
            }
            b'v' => {
                let i = self.index();
                if i < 0 {
                    return None;
                }
                if self.next_if(b"r") {
                    return Some(self.node_index(K::OutlinedReadOnlyObject, i));
                }
                Some(self.node_index(K::OutlinedVariable, i))
            }
            b'e' => {
                let params = self.bridged_method_params();
                if params.is_empty() {
                    return None;
                }
                Some(self.make(K::OutlinedBridgedMethod, Some(&params), None))
            }
            b'u' => Some(self.node(K::AsyncFunctionPointer)),
            b'U' => {
                let actor = self.pop_kind(K::Type)?;
                let reabstraction = self.pop()?;
                self.with(K::ReabstractionThunkHelperWithGlobalActor, &[Some(reabstraction), Some(actor)])
            }
            b'w' => match self.next() {
                b'b' => Some(self.node(K::BackDeploymentThunk)),
                b'B' => Some(self.node(K::BackDeploymentFallback)),
                b'S' => Some(self.node(K::HasSymbolQuery)),
                _ => None,
            },
            _ => None,
        }
    }

    fn bridged_method_params(&mut self) -> String {
        if self.next_if(b"_") {
            return String::new();
        }
        let mut out = String::new();
        let kind = self.next();
        if !b"nbgo".contains(&kind) {
            return String::new();
        }
        out.push(kind as char);
        while !self.next_if(b"_") {
            let k = self.next();
            if !b"nbgo".contains(&k) {
                return String::new();
            }
            out.push(k as char);
        }
        out
    }

    fn spec_attributes(&mut self, kind: Kind) -> N {
        let metatypes_removed = self.next_if(b"m");
        let serialized = self.next_if(b"q");
        let async_removed = self.next_if(b"a");
        let pass = self.next();
        if !is_digit(pass) {
            return None;
        }
        let spec = self.node(kind);
        if metatypes_removed {
            let n = self.node(K::MetatypeParamsRemoved);
            self.push_child(spec, n);
        }
        if serialized {
            let n = self.node(K::IsSerialized);
            self.push_child(spec, n);
        }
        if async_removed {
            let n = self.node(K::AsyncRemoved);
            self.push_child(spec, n);
        }
        let n = self.node_index(K::SpecializationPassID, (pass - b'0') as i64);
        self.push_child(spec, n);
        Some(spec)
    }

    fn generic_specialization(&mut self, kind: Kind, dropped: Vec<NodeId>) -> N {
        let spec = self.spec_attributes(kind)?;
        self.extend_children(spec, &dropped);
        let list = self.pop_type_list()?;
        let types: Vec<NodeId> = self.children_of(list);
        for t in types {
            let param = self.with(K::GenericSpecializationParam, &[Some(t)]).unwrap();
            self.push_child(spec, param);
        }
        Some(spec)
    }

    fn generic_specialization_with_dropped_arguments(&mut self) -> N {
        self.back();
        let mut dropped = Vec::new();
        while self.next_if(b"t") {
            let n = self.natural();
            dropped.push(self.node_index(K::DroppedArgument, if n < 0 { 0 } else { n + 1 }));
        }
        let kind = match self.next() {
            b'g' => K::GenericSpecialization,
            b'G' => K::GenericSpecializationNotReAbstracted,
            b'B' => K::GenericSpecializationInResilienceDomain,
            b's' => K::GenericSpecializationPrespecialized,
            b'i' => K::InlinedGenericFunction,
            _ => return None,
        };
        self.generic_specialization(kind, dropped)
    }

    fn function_specialization(&mut self) -> N {
        let mut spec = self.spec_attributes(K::FunctionSignatureSpecialization);
        while spec.is_some() && !self.next_if(b"_") {
            if self.pos >= self.s.len() {
                return None;
            }
            let param = self.func_spec_param(K::FunctionSignatureSpecializationParam);
            spec = self.add(spec, param);
        }
        if !self.next_if(b"n") {
            let ret = self.func_spec_param(K::FunctionSignatureSpecializationReturn);
            spec = self.add(spec, ret);
        }
        let spec = spec?;
        for i in (0..self.count(spec)).rev() {
            let param = self.child(spec, i);
            if self.kind(param) != K::FunctionSignatureSpecializationParam || self.count(param) == 0 {
                continue;
            }
            let kind_node = self.first(param);
            let Some(kind) = self.t.index(kind_node) else { continue };
            let closure = kind == fss::CLOSURE_PROP || kind == fss::CLOSURE_PROP_PREVIOUS_ARG || kind == fss::CLOSURE_PROP_ESCAPING;
            if !closure && ![fss::CONSTANT_PROP_FUNCTION, fss::CONSTANT_PROP_GLOBAL, fss::CONSTANT_PROP_STRING, fss::CONSTANT_PROP_KEY_PATH].contains(&kind) {
                continue;
            }
            let mut types = Vec::new();
            while let Some(t) = self.pop_kind(K::Type) {
                if !closure && kind != fss::CONSTANT_PROP_KEY_PATH {
                    return None;
                }
                types.push(t);
            }
            let name = self.pop_kind(K::Identifier)?;
            // The payload is the identifier's text, without the leading `_` of a string.
            let (mut at, mut len) = (self.t.nodes[name as usize].text_at, self.t.nodes[name as usize].text_len);
            if len == NO_TEXT {
                (at, len) = (self.t.texts.len() as u32, 0);
            }
            if kind == fss::CONSTANT_PROP_STRING && self.text(name).is_some_and(|t| t.starts_with('_')) {
                at += 1;
                len -= 1;
            }
            let payload = self.make_at(K::FunctionSignatureSpecializationParamPayload, at as usize, len, None);
            types.push(payload);
            types.reverse();
            self.extend_children(param, &types);
        }
        Some(spec)
    }

    fn func_spec_param(&mut self, kind: Kind) -> N {
        let param = self.node(kind);
        let with_kind = |d: &mut Self, k: i64| {
            let n = d.node_index(K::FunctionSignatureSpecializationParamKind, k);
            d.push_child(param, n);
            Some(param)
        };
        match self.next() {
            b'n' => Some(param),
            b'c' => with_kind(self, fss::CLOSURE_PROP),
            b'E' => with_kind(self, fss::CLOSURE_PROP_ESCAPING),
            b'C' => {
                with_kind(self, fss::CLOSURE_PROP_PREVIOUS_ARG);
                let n = self.natural();
                if n < 0 {
                    return None;
                }
                let payload = self.make(K::FunctionSignatureSpecializationParamPayload, Some(&n.to_string()), None);
                self.push_child(param, payload);
                Some(param)
            }
            b'p' => match self.next() {
                b'f' => with_kind(self, fss::CONSTANT_PROP_FUNCTION),
                b'g' => with_kind(self, fss::CONSTANT_PROP_GLOBAL),
                c @ (b'i' | b'd') => {
                    with_kind(self, if c == b'i' { fss::CONSTANT_PROP_INTEGER } else { fss::CONSTANT_PROP_FLOAT });
                    let mut digits = String::new();
                    if self.peek() == b'-' {
                        digits.push(self.next() as char);
                    }
                    while is_digit(self.peek()) {
                        digits.push(self.next() as char);
                    }
                    if digits.is_empty() {
                        return None;
                    }
                    let payload = self.make(K::FunctionSignatureSpecializationParamPayload, Some(&digits), None);
                    self.push_child(param, payload);
                    Some(param)
                }
                b's' => {
                    let encoding = match self.next() {
                        b'b' => "u8",
                        b'w' => "u16",
                        b'c' => "objc",
                        _ => return None,
                    };
                    with_kind(self, fss::CONSTANT_PROP_STRING);
                    let payload = self.node_text(K::FunctionSignatureSpecializationParamPayload, encoding);
                    self.push_child(param, payload);
                    Some(param)
                }
                b'k' => with_kind(self, fss::CONSTANT_PROP_KEY_PATH),
                _ => None,
            },
            b'e' => {
                let mut v = fss::EXISTENTIAL_TO_GENERIC;
                if self.next_if(b"D") {
                    v |= fss::DEAD;
                }
                if self.next_if(b"G") {
                    v |= fss::OWNED_TO_GUARANTEED;
                }
                if self.next_if(b"O") {
                    v |= fss::GUARANTEED_TO_OWNED;
                }
                if self.next_if(b"X") {
                    v |= fss::SROA;
                }
                with_kind(self, v)
            }
            b'd' => {
                let mut v = fss::DEAD;
                if self.next_if(b"G") {
                    v |= fss::OWNED_TO_GUARANTEED;
                }
                if self.next_if(b"O") {
                    v |= fss::GUARANTEED_TO_OWNED;
                }
                if self.next_if(b"X") {
                    v |= fss::SROA;
                }
                with_kind(self, v)
            }
            b'g' => {
                let mut v = fss::OWNED_TO_GUARANTEED;
                if self.next_if(b"X") {
                    v |= fss::SROA;
                }
                with_kind(self, v)
            }
            b'o' => {
                let mut v = fss::GUARANTEED_TO_OWNED;
                if self.next_if(b"X") {
                    v |= fss::SROA;
                }
                with_kind(self, v)
            }
            b'x' => with_kind(self, fss::SROA),
            b'i' => with_kind(self, fss::BOX_TO_VALUE),
            b's' => with_kind(self, fss::BOX_TO_STACK),
            b'r' => with_kind(self, fss::IN_OUT_TO_OUT),
            _ => None,
        }
    }

    fn impl_function_type(&mut self) -> N {
        let mut ty: N = Some(self.node(K::ImplFunctionType));
        let fun = ty.unwrap();
        if self.next_if(b"s") {
            let mut lists = Vec::new();
            let (ok, retro) = self.bound_generics(&mut lists);
            if !ok {
                return None;
            }
            let sig = self.pop_kind(K::DependentGenericSignature)?;
            let subs = self.node(K::ImplPatternSubstitutions);
            self.push_child(subs, sig);
            self.push_child(subs, lists[0]);
            self.add_if(subs, retro);
            self.push_child(fun, subs);
        }
        if self.next_if(b"I") {
            let mut lists = Vec::new();
            let (ok, retro) = self.bound_generics(&mut lists);
            if !ok {
                return None;
            }
            let subs = self.node(K::ImplInvocationSubstitutions);
            self.push_child(subs, lists[0]);
            self.add_if(subs, retro);
            self.push_child(fun, subs);
        }
        let mut sig = self.pop_kind(K::DependentGenericSignature);
        if sig.is_some() && self.next_if(b"P") {
            sig = self.change_kind(sig, K::DependentPseudogenericSignature);
        }
        if self.next_if(b"e") {
            let n = self.node(K::ImplEscaping);
            self.push_child(fun, n);
        }
        if self.next_if(b"A") {
            let n = self.node(K::ImplErasedIsolation);
            self.push_child(fun, n);
        }
        if b"dlfr".contains(&self.peek()) {
            let c = self.next();
            let n = self.node_char(K::ImplDifferentiabilityKind, c);
            self.push_child(fun, n);
        }
        let callee = match self.next() {
            b'y' => "@callee_unowned",
            b'g' => "@callee_guaranteed",
            b'x' => "@callee_owned",
            b't' => "@convention(thin)",
            _ => return None,
        };
        let n = self.node_text(K::ImplConvention, callee);
        self.push_child(fun, n);
        let mut conv: Option<&str> = None;
        let mut clang = false;
        match self.next() {
            b'B' => conv = Some("block"),
            b'C' => conv = Some("c"),
            b'z' => match self.next() {
                b'B' => {
                    clang = true;
                    conv = Some("block");
                }
                b'C' => {
                    clang = true;
                    conv = Some("c");
                }
                _ => {
                    self.back();
                    self.back();
                }
            },
            b'M' => conv = Some("method"),
            b'O' => conv = Some("objc_method"),
            b'K' => conv = Some("closure"),
            b'W' => conv = Some("witness_method"),
            _ => self.back(),
        }
        if let Some(conv) = conv {
            let attr = self.node(K::ImplFunctionConvention);
            let name = self.node_text(K::ImplFunctionConventionName, conv);
            self.push_child(attr, name);
            if clang {
                let ct = self.clang_type()?;
                self.push_child(attr, ct);
            }
            self.push_child(fun, attr);
        }
        let coro = if self.next_if(b"A") {
            Some("@yield_once")
        } else if self.next_if(b"I") {
            Some("@yield_once_2")
        } else if self.next_if(b"G") {
            Some("@yield_many")
        } else {
            None
        };
        if let Some(coro) = coro {
            let n = self.node_text(K::ImplCoroutineKind, coro);
            self.push_child(fun, n);
        }
        if self.next_if(b"h") {
            let n = self.node_text(K::ImplFunctionAttribute, "@Sendable");
            self.push_child(fun, n);
        }
        if self.next_if(b"H") {
            let n = self.node_text(K::ImplFunctionAttribute, "@async");
            self.push_child(fun, n);
        }
        if self.next_if(b"T") {
            let n = self.node(K::ImplSendingResult);
            self.push_child(fun, n);
        }
        self.add_if(fun, sig);
        let mut count = 0usize;
        while let Some(p) = self.impl_param(K::ImplParameter) {
            ty = self.add(ty, Some(p));
            let diff = self.impl_differentiability();
            self.add_if(p, diff);
            if self.next_if(b"T") {
                let n = self.node_text(K::ImplParameterSending, "sending");
                self.push_child(p, n);
            }
            if self.next_if(b"I") {
                let n = self.node_text(K::ImplParameterIsolated, "isolated");
                self.push_child(p, n);
            }
            if self.next_if(b"L") {
                let n = self.node_text(K::ImplParameterImplicitLeading, "sil_implicit_leading_param");
                self.push_child(p, n);
            }
            count += 1;
        }
        while let Some(r) = self.impl_result(K::ImplResult) {
            ty = self.add(ty, Some(r));
            let diff = self.impl_differentiability();
            self.add_if(r, diff);
            count += 1;
        }
        while self.next_if(b"Y") {
            let y = self.impl_param(K::ImplYield)?;
            ty = self.add(ty, Some(y));
            count += 1;
        }
        if self.next_if(b"z") {
            let e = self.impl_result(K::ImplErrorResult)?;
            ty = self.add(ty, Some(e));
            count += 1;
        }
        if !self.next_if(b"_") {
            return None;
        }
        let ty = ty?;
        for i in 0..count {
            let t = self.pop_kind(K::Type)?;
            let total = self.count(ty);
            if total < i + 1 {
                self.bad = true;
                return None;
            }
            let c = self.child(ty, total - i - 1);
            self.push_child(c, t);
        }
        self.type_(Some(ty))
    }

    fn impl_differentiability(&mut self) -> N {
        if self.next_if(b"w") {
            return Some(self.node_text(K::ImplParameterResultDifferentiability, "@noDerivative"));
        }
        None
    }

    fn impl_param(&mut self, kind: Kind) -> N {
        let attr = match self.next() {
            b'i' => "@in",
            b'c' => "@in_constant",
            b'l' => "@inout",
            b'b' => "@inout_aliasable",
            b'n' => "@in_guaranteed",
            b'X' => "@in_cxx",
            b'x' => "@owned",
            b'g' => "@guaranteed",
            b'e' => "@deallocating",
            b'y' => "@unowned",
            b'v' => "@pack_owned",
            b'p' => "@pack_guaranteed",
            b'm' => "@pack_inout",
            _ => {
                self.back();
                return None;
            }
        };
        let c = self.node_text(K::ImplConvention, attr);
        self.with(kind, &[Some(c)])
    }

    fn impl_result(&mut self, kind: Kind) -> N {
        let attr = match self.next() {
            b'r' => "@out",
            b'o' => "@owned",
            b'd' => "@unowned",
            b'u' => "@unowned_inner_pointer",
            b'a' => "@autoreleased",
            b'k' => "@pack_out",
            _ => {
                self.back();
                return None;
            }
        };
        let c = self.node_text(K::ImplConvention, attr);
        self.with(kind, &[Some(c)])
    }

    fn is_protocol_node(&self, t: NodeId) -> bool {
        let k = if self.kind(t) == K::Type {
            match self.t.children(t).first() {
                Some(&c) => self.kind(c),
                None => return false,
            }
        } else {
            self.kind(t)
        };
        matches!(k, K::Protocol | K::ProtocolSymbolicReference | K::ObjectiveCProtocolSymbolicReference)
    }
}

/// JavaScript's ToInt32, for the `>> 1` of punycode's bias adaptation.
fn to_int32(x: f64) -> i32 {
    if !x.is_finite() {
        return 0;
    }
    let t = x.trunc() % 4294967296.0;
    let t = if t < 0.0 { t + 4294967296.0 } else { t };
    t as u64 as u32 as i32
}

/// Punycode as Swift encodes identifiers that are not ASCII: `_` is the delimiter, digits are a–z then A–J.
/// The decoded text goes onto `out` as UTF-16 code units; None when it does not decode. The arithmetic is
/// JavaScript's, in doubles. The input is the name's units as the parser reads them (0x80 for any unit
/// that is not ASCII, which is no digit and fails the basic part, as the unit itself did).
fn punycode(input: &[u8], out: &mut Vec<u16>) -> Option<()> {
    const BASE: f64 = 36.0;
    const T_MIN: f64 = 1.0;
    const T_MAX: f64 = 26.0;
    const SKEW: f64 = 38.0;
    const DAMP: f64 = 700.0;
    let mut n = 128.0f64;
    let mut i = 0.0f64;
    let mut bias = 72.0f64;
    let mut points: Vec<u32> = Vec::new();
    let mut pos = 0;
    if let Some(delimiter) = input.iter().rposition(|&c| c == b'_') {
        for &c in &input[..delimiter] {
            if c >= 0x80 {
                return None;
            }
            points.push(c as u32);
        }
        pos = delimiter + 1;
    }
    let digit = |c: u8| -> f64 {
        match c {
            b'a'..=b'z' => (c - b'a') as f64,
            b'A'..=b'J' => (c - b'A' + 26) as f64,
            _ => -1.0,
        }
    };
    let adapt = |delta: f64, count: f64, first: bool| -> f64 {
        let mut delta = if first { (delta / DAMP).floor() } else { (to_int32(delta) >> 1) as f64 };
        delta += (delta / count).floor();
        let mut k = 0.0;
        while delta > (((BASE - T_MIN) * T_MAX) as i32 >> 1) as f64 {
            delta = (delta / (BASE - T_MIN)).floor();
            k += BASE;
        }
        k + (((BASE - T_MIN + 1.0) * delta) / (delta + SKEW)).floor()
    };
    while pos < input.len() {
        let old_i = i;
        let mut w = 1.0f64;
        let mut k = BASE;
        loop {
            if pos >= input.len() {
                return None;
            }
            let d = digit(input[pos]);
            pos += 1;
            if d < 0.0 {
                return None;
            }
            i += d * w;
            let t = if k <= bias {
                T_MIN
            } else if k >= bias + T_MAX {
                T_MAX
            } else {
                k - bias
            };
            if d < t {
                break;
            }
            w *= BASE - t;
            k += BASE;
        }
        let count = (points.len() + 1) as f64;
        bias = adapt(i - old_i, count, old_i == 0.0);
        n += (i / count).floor();
        i %= count;
        // Swift maps the surrogate range above 0xD800 to keep invalid code points out.
        if (0xd800 as f64..=0xd880 as f64).contains(&n) {
            n -= 0xd800 as f64;
        }
        if n > 0x10ffff as f64 {
            return None;
        }
        points.insert(i as usize, n as u32);
        i += 1.0;
    }
    // String.fromCodePoint: UTF-16, a value in the surrogate range staying a single unit.
    for p in points {
        if p > 0xffff {
            let p = p - 0x10000;
            out.push(0xd800 + (p >> 10) as u16);
            out.push(0xdc00 + (p & 0x3ff) as u16);
        } else {
            out.push(p as u16);
        }
    }
    Some(())
}

/// The tree of a symbol (None when it does not parse).
pub fn parse_swift(symbol: &str) -> Option<Tree> {
    let u = Units::new(symbol);
    let mut d = Demangler::new(&u);
    let root = d.demangle_symbol()?;
    let mut tree = d.t;
    tree.root = root;
    Some(tree)
}

/// The tree as `swift-demangle --tree-only` prints it, for comparing the two.
pub fn swift_tree(tree: &Tree) -> String {
    fn walk(t: &Tree, n: NodeId, depth: usize, out: &mut String) {
        if depth > 0 {
            out.push('\n');
        }
        out.push_str(&" ".repeat(depth * 2));
        out.push_str("kind=");
        out.push_str(t.kind(n).name());
        if let Some(text) = t.text(n) {
            out.push_str(&format!(", text=\"{text}\""));
        } else if let Some(index) = t.index(n) {
            out.push_str(&format!(", index={index}"));
        }
        for &c in t.children(n) {
            walk(t, c, depth + 1, out);
        }
    }
    let mut out = String::new();
    walk(tree, tree.root, 0, &mut out);
    out
}

/* ------------------------------------------------------------------ *
 * Printing
 * ------------------------------------------------------------------ */

#[derive(Clone, Copy)]
struct Options {
    synthesize_sugar_on_types: bool,
    display_module_names: bool,
    display_extension_contexts: bool,
    display_unmangled_suffix: bool,
    display_generic_specializations: bool,
    display_protocol_conformances: bool,
    display_where_clauses: bool,
    display_entity_types: bool,
    shorten_partial_apply: bool,
    shorten_thunk: bool,
    shorten_value_witness: bool,
    show_private_discriminators: bool,
    show_function_argument_types: bool,
    show_async_resume_partial: bool,
}

/// What `swift-demangle` prints by default.
const FULL: Options = Options {
    synthesize_sugar_on_types: true,
    display_module_names: true,
    display_extension_contexts: true,
    display_unmangled_suffix: true,
    display_generic_specializations: true,
    display_protocol_conformances: true,
    display_where_clauses: true,
    display_entity_types: true,
    shorten_partial_apply: false,
    shorten_thunk: false,
    shorten_value_witness: false,
    show_private_discriminators: true,
    show_function_argument_types: true,
    show_async_resume_partial: true,
};

/// What `swift-demangle --simplified` prints.
const SIMPLIFIED: Options = Options {
    synthesize_sugar_on_types: true,
    display_module_names: false,
    display_extension_contexts: false,
    display_unmangled_suffix: false,
    display_generic_specializations: false,
    display_protocol_conformances: false,
    display_where_clauses: false,
    display_entity_types: false,
    shorten_partial_apply: true,
    shorten_thunk: true,
    shorten_value_witness: true,
    show_private_discriminators: false,
    show_function_argument_types: false,
    show_async_resume_partial: false,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum TypePrinting {
    None,
    Colon,
    Function,
}

/// A node the printer does not know, or a tree of the wrong shape.
struct Bad;

/// How deep names printed inside names (constant-propagated functions) may nest.
const MAX_NESTED_NAMES: u32 = 32;

type R<T> = Result<T, Bad>;

/// Prefixes that are printed before their one child, and nothing else.
fn prefixed(k: Kind) -> Option<&'static str> {
    Some(match k {
        K::CurryThunk => "curry thunk of ",
        K::DispatchThunk => "dispatch thunk of ",
        K::MethodDescriptor => "method descriptor for ",
        K::MethodLookupFunction => "method lookup function for ",
        K::ObjCMetadataUpdateFunction => "ObjC metadata update function for ",
        K::ObjCResilientClassStub => "ObjC resilient class stub for ",
        K::FullObjCResilientClassStub => "full ObjC resilient class stub for ",
        K::OutlinedCopy => "outlined copy of ",
        K::OutlinedConsume => "outlined consume of ",
        K::OutlinedRetain => "outlined retain of ",
        K::OutlinedRelease => "outlined release of ",
        K::OutlinedInitializeWithTake => "outlined init with take of ",
        K::OutlinedInitializeWithCopy => "outlined init with copy of ",
        K::OutlinedAssignWithTake => "outlined assign with take of ",
        K::OutlinedAssignWithCopy => "outlined assign with copy of ",
        K::OutlinedDestroy => "outlined destroy of ",
        K::OutlinedInitializeWithTakeNoValueWitness => "outlined init with take of ",
        K::OutlinedInitializeWithCopyNoValueWitness => "outlined init with copy of ",
        K::OutlinedAssignWithTakeNoValueWitness => "outlined assign with take of ",
        K::OutlinedAssignWithCopyNoValueWitness => "outlined assign with copy of ",
        K::OutlinedDestroyNoValueWitness => "outlined destroy of ",
        K::OutlinedEnumGetTag => "outlined enum get tag of ",
        K::OutlinedEnumTagStore => "outlined enum tag store of ",
        K::OutlinedEnumProjectDataForLoad => "outlined enum project data for load of ",
        K::ProtocolSelfConformanceWitness => "protocol self-conformance witness for ",
        K::ProtocolSelfConformanceWitnessTable => "protocol self-conformance witness table for ",
        K::ProtocolWitnessTable => "protocol witness table for ",
        K::ProtocolWitnessTablePattern => "protocol witness table pattern for ",
        K::GenericProtocolWitnessTable => "generic protocol witness table for ",
        K::GenericProtocolWitnessTableInstantiationFunction => "instantiation function for generic protocol witness table for ",
        K::ResilientProtocolWitnessTable => "resilient protocol witness table for ",
        K::ProtocolWitnessTableAccessor => "protocol witness table accessor for ",
        K::EnumCase => "enum case for ",
        K::ValueWitnessTable => "value witness table for ",
        K::ProtocolConformanceDescriptor => "protocol conformance descriptor for ",
        K::ProtocolDescriptor => "protocol descriptor for ",
        K::ProtocolRequirementsBaseDescriptor => "protocol requirements base descriptor for ",
        K::FullTypeMetadata => "full type metadata for ",
        K::TypeMetadata => "type metadata for ",
        K::TypeMetadataAccessFunction => "type metadata accessor for ",
        K::TypeMetadataInstantiationCache => "type metadata instantiation cache for ",
        K::TypeMetadataInstantiationFunction => "type metadata instantiation function for ",
        K::TypeMetadataSingletonInitializationCache => "type metadata singleton initialization cache for ",
        K::TypeMetadataCompletionFunction => "type metadata completion function for ",
        K::TypeMetadataDemanglingCache => "demangling cache variable for type metadata for ",
        K::TypeMetadataLazyCache => "lazy cache variable for type metadata for ",
        K::TypeMetadataMangledNameRef => "mangled name ref for type metadata for ",
        K::Metaclass => "metaclass for ",
        K::NominalTypeDescriptor => "nominal type descriptor for ",
        K::NominalTypeDescriptorRecord => "nominal type descriptor runtime record for ",
        K::OpaqueTypeDescriptor => "opaque type descriptor for ",
        K::OpaqueTypeDescriptorRecord => "opaque type descriptor runtime record for ",
        K::OpaqueTypeDescriptorAccessor => "opaque type descriptor accessor for ",
        K::OpaqueTypeDescriptorAccessorImpl => "opaque type descriptor accessor impl for ",
        K::OpaqueTypeDescriptorAccessorKey => "opaque type descriptor accessor key for ",
        K::OpaqueTypeDescriptorAccessorVar => "opaque type descriptor accessor var for ",
        K::PropertyDescriptor => "property descriptor for ",
        K::ClassMetadataBaseOffset => "class metadata base offset for ",
        K::GenericTypeMetadataPattern => "generic type metadata pattern for ",
        K::ReflectionMetadataBuiltinDescriptor => "reflection metadata builtin descriptor ",
        K::ReflectionMetadataFieldDescriptor => "reflection metadata field descriptor ",
        K::ReflectionMetadataAssocTypeDescriptor => "reflection metadata associated type descriptor ",
        K::ReflectionMetadataSuperclassDescriptor => "reflection metadata superclass descriptor ",
        K::ProtocolConformanceDescriptorRecord => "protocol conformance descriptor runtime record for ",
        K::ProtocolDescriptorRecord => "protocol descriptor runtime record for ",
        K::ProtocolSelfConformanceDescriptor => "protocol self-conformance descriptor for ",
        K::CanonicalSpecializedGenericMetaclass => "specialized generic metaclass for ",
        K::CanonicalSpecializedGenericTypeMetadataAccessFunction => "canonical specialized generic type metadata accessor for ",
        K::NoncanonicalSpecializedGenericTypeMetadata => "noncanonical specialized generic type metadata for ",
        K::NoncanonicalSpecializedGenericTypeMetadataCache => "cache variable for noncanonical specialized generic type metadata for ",
        K::CanonicalPrespecializedGenericTypeCachingOnceToken => "flag for loading of canonical specialized generic type metadata for ",
        K::MetadataInstantiationCache => "metadata instantiation cache for ",
        K::Uniquable => "uniquable ",
        K::AssociatedTypeDescriptor => "associated type descriptor for ",
        K::DefaultAssociatedTypeMetadataAccessor => "default associated type metadata accessor for ",
        K::ExtensionDescriptor => "extension descriptor ",
        K::ModuleDescriptor => "module descriptor ",
        K::CoroutineContinuationPrototype => "coroutine continuation prototype for ",
        K::SILThunkIdentity => "identity thunk of ",
        K::SILThunkHopToMainActorIfNeeded => "hop to main actor thunk of ",
        K::Shared => "__shared ",
        K::Owned => "__owned ",
        K::InOut => "inout ",
        K::Isolated => "isolated ",
        K::Sending => "sending ",
        K::CompileTimeLiteral => "_const ",
        K::ConstValue => "@const ",
        K::NoDerivative => "@noDerivative ",
        K::Weak => "weak ",
        K::Unowned => "unowned ",
        K::Unmanaged => "unowned(unsafe) ",
        K::SILBoxType => "@box ",
        _ => return None,
    })
}

/// Accessors: the word printed after the variable or subscript.
fn accessor_word(k: Kind) -> Option<&'static str> {
    Some(match k {
        K::Getter => "getter",
        K::Setter => "setter",
        K::MaterializeForSet => "materializeForSet",
        K::WillSet => "willset",
        K::DidSet => "didset",
        K::ReadAccessor => "read",
        K::Read2Accessor => "yielding_borrow",
        K::ModifyAccessor => "modify",
        K::Modify2Accessor => "yielding_mutate",
        K::InitAccessor => "init",
        K::UnsafeAddressor => "unsafeAddressor",
        K::UnsafeMutableAddressor => "unsafeMutableAddressor",
        K::OwningAddressor => "owningAddressor",
        K::OwningMutableAddressor => "owningMutableAddressor",
        K::NativeOwningAddressor => "nativeOwningAddressor",
        K::NativeOwningMutableAddressor => "nativeOwningMutableAddressor",
        K::NativePinningAddressor => "nativePinningAddressor",
        K::NativePinningMutableAddressor => "nativePinningMutableAddressor",
        K::GlobalGetter => "getter",
        _ => return None,
    })
}

fn is_simple_kind(k: Kind) -> bool {
    matches!(
        k,
        K::AssociatedType
            | K::AssociatedTypeRef
            | K::BoundGenericClass
            | K::BoundGenericEnum
            | K::BoundGenericStructure
            | K::BoundGenericProtocol
            | K::BoundGenericOtherNominalType
            | K::BoundGenericTypeAlias
            | K::BoundGenericFunction
            | K::BuiltinTypeName
            | K::BuiltinTupleType
            | K::Class
            | K::DependentGenericType
            | K::DependentMemberType
            | K::DependentGenericParamType
            | K::DynamicSelf
            | K::Enum
            | K::ErrorType
            | K::ExistentialMetatype
            | K::Metatype
            | K::MetatypeRepresentation
            | K::Module
            | K::Tuple
            | K::Pack
            | K::ConstrainedExistentialRequirementList
            | K::ConstrainedExistentialSelf
            | K::Protocol
            | K::ProtocolSymbolicReference
            | K::ReturnType
            | K::SILBoxType
            | K::SILBoxTypeWithLayout
            | K::Structure
            | K::OtherNominalType
            | K::TupleElementName
            | K::TypeAlias
            | K::TypeList
            | K::LabelList
            | K::TypeSymbolicReference
            | K::SugaredOptional
            | K::SugaredArray
            | K::SugaredDictionary
            | K::SugaredParen
    )
}

fn generic_parameter_name(out: &mut String, depth: i64, mut index: i64) {
    loop {
        out.push((b'A' + (index % 26) as u8) as char);
        index /= 26;
        if index == 0 {
            break;
        }
    }
    if depth != 0 {
        out.push_str(&depth.to_string());
    }
}

fn is_existential(k: Kind) -> bool {
    matches!(k, K::ExistentialMetatype | K::ProtocolList | K::ProtocolListWithClass | K::ProtocolListWithAnyObject)
}

/// JSON.stringify for a string.
fn json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sugar {
    None,
    Optional,
    Implicit,
    Array,
    Dictionary,
}

struct Printer<'t> {
    t: &'t Tree,
    out: String,
    o: Options,
    specialization_prefix_printed: bool,
    /// How many names the one being printed sits inside (as a constant-propagated function's name).
    nested: u32,
}

impl<'t> Printer<'t> {
    fn new(t: &'t Tree, o: Options) -> Self {
        Printer { t, out: String::new(), o, specialization_prefix_printed: false, nested: 0 }
    }

    fn children(&self, n: NodeId) -> &'t [NodeId] {
        self.t.children(n)
    }
    fn kind(&self, n: NodeId) -> Kind {
        self.t.kind(n)
    }
    fn count(&self, n: NodeId) -> usize {
        self.t.children(n).len()
    }
    fn child(&self, n: NodeId, i: usize) -> R<NodeId> {
        self.t.children(n).get(i).copied().ok_or(Bad)
    }
    fn first(&self, n: NodeId) -> R<NodeId> {
        self.child(n, 0)
    }
    fn find(&self, n: NodeId, kind: Kind) -> Option<NodeId> {
        self.t.children(n).iter().copied().find(|&c| self.t.kind(c) == kind)
    }
    /// The text of a node, or what JavaScript wrote for a missing one.
    fn text(&self, n: NodeId) -> &'t str {
        self.t.text(n).unwrap_or("undefined")
    }
    fn index(&self, n: NodeId) -> Option<i64> {
        self.t.index(n)
    }

    fn print_children(&mut self, n: NodeId, depth: u32, separator: &str) -> R<()> {
        let children = self.children(n);
        for (i, &c) in children.iter().enumerate() {
            if i > 0 {
                self.out.push_str(separator);
            }
            self.print(c, depth + 1, false)?;
        }
        Ok(())
    }

    fn is_simple_type(&self, n: NodeId) -> R<bool> {
        match self.kind(n) {
            K::Type => self.is_simple_type(self.first(n)?),
            K::ProtocolList => Ok(self.count(self.first(n)?) <= 1),
            K::ProtocolListWithAnyObject => Ok(self.count(self.first(self.first(n)?)?) == 0),
            k => Ok(is_simple_kind(k)),
        }
    }

    fn print_with_parens(&mut self, t: NodeId, depth: u32) -> R<()> {
        let parens = !self.is_simple_type(t)?;
        if parens {
            self.out.push('(');
        }
        self.print(t, depth + 1, false)?;
        if parens {
            self.out.push(')');
        }
        Ok(())
    }

    fn need_space_before_type(&self, t: NodeId) -> R<bool> {
        match self.kind(t) {
            K::Type => self.need_space_before_type(self.first(t)?),
            K::FunctionType | K::NoEscapeFunctionType | K::UncurriedFunctionType | K::DependentGenericType => Ok(false),
            _ => Ok(true),
        }
    }

    /// Prints the nodes at the given indices of `n`'s children.
    fn print_at(&mut self, n: NodeId, i: usize, depth: u32) -> R<()> {
        let c = self.child(n, i)?;
        self.print(c, depth + 1, false)?;
        Ok(())
    }

    fn print(&mut self, n: NodeId, depth: u32, as_prefix: bool) -> R<N> {
        if depth > 768 {
            return Err(Bad);
        }
        let k = self.kind(n);
        if let Some(prefix) = prefixed(k) {
            self.out.push_str(prefix);
            self.print_at(n, 0, depth)?;
            // An outlined copy or consume names the generic signature it was made under.
            if (k == K::OutlinedCopy || k == K::OutlinedConsume) && self.count(n) > 1 {
                self.print_at(n, 1, depth)?;
            }
            return Ok(None);
        }
        if let Some(word) = accessor_word(k) {
            return self.print_abstract_storage(self.first(n)?, depth, as_prefix, word);
        }
        match k {
            K::Global => self.print_children(n, depth, "")?,
            K::Static => {
                self.out.push_str("static ");
                self.print_at(n, 0, depth)?;
            }
            K::Suffix => {
                if self.o.display_unmangled_suffix {
                    self.out.push_str(" with unmangled suffix ");
                    let text = self.text(n);
                    json_string(&mut self.out, text);
                }
            }
            K::Initializer => return self.print_entity(n, depth, as_prefix, TypePrinting::None, false, "variable initialization expression", -1, ""),
            K::PropertyWrapperBackingInitializer => return self.print_entity(n, depth, as_prefix, TypePrinting::None, false, "property wrapper backing initializer", -1, ""),
            K::PropertyWrapperInitFromProjectedValue => {
                return self.print_entity(n, depth, as_prefix, TypePrinting::None, false, "property wrapper init from projected value", -1, "")
            }
            K::PropertyWrappedFieldInitAccessor => return self.print_entity(n, depth, as_prefix, TypePrinting::None, false, "property wrapped field init accessor", -1, ""),
            K::DefaultArgumentInitializer => {
                let index = self.index(self.child(n, 1)?).unwrap_or(-1);
                return self.print_entity(n, depth, as_prefix, TypePrinting::None, false, "default argument ", index, "");
            }
            K::DeclContext | K::Type => self.print_at(n, 0, depth)?,
            K::TypeMangling => {
                let c = self.child(n, 0)?;
                if self.kind(c) == K::LabelList {
                    let f = self.first(self.child(n, 1)?)?;
                    self.print_function_type(Some(c), f, depth)?;
                } else {
                    self.print(c, depth + 1, false)?;
                }
            }
            K::Class | K::Structure | K::Enum | K::Protocol | K::TypeAlias | K::OtherNominalType => {
                return self.print_entity(n, depth, as_prefix, TypePrinting::None, true, "", -1, "")
            }
            K::LocalDeclName => {
                self.print_at(n, 1, depth)?;
                self.out.push_str(" #");
                self.push_plus_one(self.index(self.child(n, 0)?));
            }
            K::PrivateDeclName => {
                if self.count(n) > 1 {
                    if self.o.show_private_discriminators {
                        self.out.push('(');
                    }
                    self.print_at(n, 1, depth)?;
                    if self.o.show_private_discriminators {
                        self.out.push_str(" in ");
                        self.out.push_str(self.text(self.child(n, 0)?));
                        self.out.push(')');
                    }
                } else if self.o.show_private_discriminators {
                    self.out.push_str("(in ");
                    self.out.push_str(self.text(self.child(n, 0)?));
                    self.out.push(')');
                }
            }
            K::RelatedEntityDeclName => {
                self.out.push_str("related decl '");
                self.out.push_str(self.text(self.first(n)?));
                self.out.push_str("' for ");
                self.print_at(n, 1, depth)?;
            }
            K::Module => {
                if self.o.display_module_names {
                    self.out.push_str(self.text(n));
                }
            }
            K::Identifier | K::ClangType | K::BuiltinTypeName | K::MetatypeRepresentation | K::FunctionSignatureSpecializationParamPayload => self.out.push_str(self.text(n)),
            K::Index => match self.t.text(n) {
                Some(text) => self.out.push_str(text),
                None => self.push_index(self.index(n)),
            },
            K::Number | K::SpecializationPassID => self.push_index(self.index(n)),
            K::UnknownIndex => self.out.push_str("unknown index"),
            K::FunctionType
            | K::UncurriedFunctionType
            | K::NoEscapeFunctionType
            | K::AutoClosureType
            | K::EscapingAutoClosureType
            | K::ThinFunctionType
            | K::CFunctionPointer
            | K::ObjCBlock
            | K::EscapingObjCBlock => self.print_function_type(None, n, depth)?,
            K::ArgumentTuple => self.print_function_parameters(None, n, depth, self.o.show_function_argument_types)?,
            K::Tuple => {
                self.out.push('(');
                self.print_children(n, depth, ", ")?;
                self.out.push(')');
            }
            K::TupleElement => {
                if let Some(label) = self.find(n, K::TupleElementName) {
                    self.out.push_str(self.text(label));
                    self.out.push_str(": ");
                }
                let t = self.find(n, K::Type).ok_or(Bad)?;
                self.print(t, depth + 1, false)?;
                if self.find(n, K::VariadicMarker).is_some() {
                    self.out.push_str("...");
                }
            }
            K::TupleElementName => {
                self.out.push_str(self.text(n));
                self.out.push_str(": ");
            }
            K::ReturnType => {
                if self.count(n) == 0 {
                    self.out.push_str(" -> ");
                    self.out.push_str(self.text(n));
                } else {
                    self.print_children(n, depth, "")?;
                }
            }
            K::Function | K::BoundGenericFunction => return self.print_entity(n, depth, as_prefix, TypePrinting::Function, true, "", -1, ""),
            K::Subscript => return self.print_entity(n, depth, as_prefix, TypePrinting::Function, false, "", -1, "subscript"),
            K::Variable => return self.print_entity(n, depth, as_prefix, TypePrinting::Colon, true, "", -1, ""),
            K::ExplicitClosure | K::ImplicitClosure => {
                let typing = if self.o.show_function_argument_types { TypePrinting::Function } else { TypePrinting::None };
                let word = if k == K::ExplicitClosure { "closure #" } else { "implicit closure #" };
                let index = self.index(self.child(n, 1)?).map_or(-1, |i| i + 1);
                return self.print_entity(n, depth, as_prefix, typing, false, word, index, "");
            }
            K::Allocator => {
                let word = if self.kind(self.child(n, 0)?) == K::Class { "__allocating_init" } else { "init" };
                return self.print_entity(n, depth, as_prefix, TypePrinting::Function, false, word, -1, "");
            }
            K::Constructor => return self.print_entity(n, depth, as_prefix, TypePrinting::Function, self.count(n) > 2, "init", -1, ""),
            K::Destructor => return self.print_entity(n, depth, as_prefix, TypePrinting::None, false, "deinit", -1, ""),
            K::Deallocator => {
                let word = if self.kind(self.child(n, 0)?) == K::Class { "__deallocating_deinit" } else { "deinit" };
                return self.print_entity(n, depth, as_prefix, TypePrinting::None, false, word, -1, "");
            }
            K::IsolatedDeallocator => {
                let word = if self.kind(self.child(n, 0)?) == K::Class { "__isolated_deallocating_deinit" } else { "deinit" };
                return self.print_entity(n, depth, as_prefix, TypePrinting::None, false, word, -1, "");
            }
            K::IVarInitializer => return self.print_entity(n, depth, as_prefix, TypePrinting::None, false, "__ivar_initializer", -1, ""),
            K::IVarDestroyer => return self.print_entity(n, depth, as_prefix, TypePrinting::None, false, "__ivar_destroyer", -1, ""),
            K::Extension => {
                if self.o.display_extension_contexts {
                    self.out.push_str("(extension in ");
                    let c = self.child(n, 0)?;
                    self.print(c, depth + 1, true)?;
                    self.out.push_str("):");
                }
                self.print_at(n, 1, depth)?;
                if self.count(n) == 3 {
                    self.print_at(n, 2, depth)?;
                }
            }
            K::AnonymousContext => {
                if self.o.display_extension_contexts {
                    self.print_at(n, 1, depth)?;
                    self.out.push_str(".(unknown context at ");
                    self.out.push_str(self.text(self.child(n, 0)?));
                    self.out.push(')');
                    if self.count(n) >= 3 && self.count(self.child(n, 2)?) > 0 {
                        self.out.push('<');
                        self.print_at(n, 2, depth)?;
                        self.out.push('>');
                    }
                }
            }
            K::InfixOperator | K::PrefixOperator | K::PostfixOperator => {
                self.out.push_str(self.text(n));
                self.out.push_str(match k {
                    K::InfixOperator => " infix",
                    K::PrefixOperator => " prefix",
                    _ => " postfix",
                });
            }
            K::BuiltinTupleType => self.out.push_str("Builtin.TheTupleType"),
            K::ObjCAttribute => self.out.push_str("@objc "),
            K::NonObjCAttribute => self.out.push_str("@nonobjc "),
            K::DynamicAttribute => self.out.push_str("dynamic "),
            K::VTableAttribute => self.out.push_str("override "),
            K::DirectMethodReferenceAttribute => self.out.push_str("super "),
            K::MergedFunction => self.push_unless_shortened("merged "),
            K::DistributedThunk => self.push_unless_shortened("distributed thunk "),
            K::DistributedAccessor => self.push_unless_shortened("distributed accessor for "),
            K::DynamicallyReplaceableFunctionImpl => self.push_unless_shortened("dynamically replaceable thunk for "),
            K::DynamicallyReplaceableFunctionKey => self.push_unless_shortened("dynamically replaceable key for "),
            K::DynamicallyReplaceableFunctionVar => self.push_unless_shortened("dynamically replaceable variable for "),
            K::BackDeploymentThunk => self.push_unless_shortened("back deployment thunk for "),
            K::BackDeploymentFallback => self.out.push_str("back deployment fallback for "),
            K::AccessibleFunctionRecord => self.push_unless_shortened("accessible function runtime record for "),
            K::HasSymbolQuery => self.out.push_str("#_hasSymbol query for "),
            K::AsyncFunctionPointer => self.out.push_str("async function pointer to "),
            K::AsyncAwaitResumePartialFunction | K::AsyncSuspendResumePartialFunction => {
                if self.o.show_async_resume_partial {
                    self.out.push('(');
                    self.print_at(n, 0, depth)?;
                    self.out.push_str(if k == K::AsyncAwaitResumePartialFunction { ") await resume partial function for " } else { ") suspend resume partial function for " });
                }
            }
            K::OutlinedVariable | K::OutlinedReadOnlyObject => {
                self.out.push_str(if k == K::OutlinedVariable { "outlined variable #" } else { "outlined read-only object #" });
                self.push_index(self.index(n));
                self.out.push_str(" of ");
            }
            K::OutlinedBridgedMethod => {
                self.out.push_str("outlined bridged method (");
                self.out.push_str(self.text(n));
                self.out.push_str(") of ");
            }
            K::PartialApplyForwarder | K::PartialApplyObjCForwarder => {
                self.out.push_str(if self.o.shorten_partial_apply {
                    "partial apply"
                } else if k == K::PartialApplyForwarder {
                    "partial apply forwarder"
                } else {
                    "partial apply ObjC forwarder"
                });
                if self.count(n) > 0 {
                    self.out.push_str(" for ");
                    self.print_children(n, depth, "")?;
                }
            }
            K::KeyPathGetterThunkHelper | K::KeyPathSetterThunkHelper => {
                self.out.push_str(if k == K::KeyPathGetterThunkHelper { "key path getter for " } else { "key path setter for " });
                self.print_at(n, 0, depth)?;
                self.out.push_str(" : ");
                for i in 1..self.count(n) {
                    if self.kind(self.child(n, i)?) != K::IsSerialized {
                        self.print_at(n, i, depth)?;
                    }
                }
                if self.find(n, K::IsSerialized).is_some() {
                    self.out.push_str(", serialized");
                }
            }
            K::KeyPathEqualsThunkHelper | K::KeyPathHashThunkHelper => {
                self.out.push_str(if k == K::KeyPathEqualsThunkHelper { "key path index equality operator for " } else { "key path index hash operator for " });
                let mut last = self.count(n) as isize - 1;
                if self.kind(self.child_at(n, last)?) == K::IsSerialized {
                    last -= 1;
                }
                if self.kind(self.child_at(n, last)?) == K::DependentGenericSignature {
                    self.print(self.child_at(n, last)?, depth + 1, false)?;
                    last -= 1;
                }
                self.out.push('(');
                let mut i = 0;
                while i <= last {
                    if i > 0 {
                        self.out.push_str(", ");
                    }
                    self.print_at(n, i as usize, depth)?;
                    i += 1;
                }
                self.out.push(')');
            }
            K::IsSerialized => self.out.push_str("serialized"),
            K::MetatypeParamsRemoved => self.out.push_str("metatypes-removed"),
            K::AsyncRemoved => self.out.push_str("async demoted"),
            K::ProtocolWitness => self.print_pair(n, "protocol witness for ", 1, " in conformance ", 0, depth)?,
            K::VTableThunk => self.print_pair(n, "vtable thunk for ", 1, " dispatching to ", 0, depth)?,
            K::LazyProtocolWitnessTableAccessor => self.print_pair(n, "lazy protocol witness table accessor for type ", 0, " and conformance ", 1, depth)?,
            K::LazyProtocolWitnessTableCacheVariable => self.print_pair(n, "lazy protocol witness table cache variable for type ", 0, " and conformance ", 1, depth)?,
            K::AssociatedTypeMetadataAccessor => self.print_pair(n, "associated type metadata accessor for ", 1, " in ", 0, depth)?,
            K::AssociatedTypeWitnessTableAccessor => {
                self.out.push_str("associated type witness table accessor for ");
                self.print_at(n, 1, depth)?;
                self.out.push_str(" : ");
                self.print_at(n, 2, depth)?;
                self.out.push_str(" in ");
                self.print_at(n, 0, depth)?;
            }
            K::BaseWitnessTableAccessor => self.print_pair(n, "base witness table accessor for ", 1, " in ", 0, depth)?,
            K::AssociatedConformanceDescriptor | K::DefaultAssociatedConformanceAccessor => {
                self.out.push_str(if k == K::AssociatedConformanceDescriptor { "associated conformance descriptor for " } else { "default associated conformance accessor for " });
                self.print_at(n, 0, depth)?;
                self.out.push('.');
                self.print_at(n, 1, depth)?;
                self.out.push_str(": ");
                self.print_at(n, 2, depth)?;
            }
            K::BaseConformanceDescriptor => self.print_pair(n, "base conformance descriptor for ", 0, ": ", 1, depth)?,
            K::AssociatedTypeGenericParamRef => {
                self.out.push_str("generic parameter reference for associated type ");
                self.print_children(n, depth, "")?;
            }
            K::AnonymousDescriptor => {
                self.out.push_str("anonymous descriptor ");
                self.print_at(n, 0, depth)?;
            }
            K::AssocTypePath => self.print_children(n, depth, ".")?,
            K::ReabstractionThunk | K::ReabstractionThunkHelper => {
                if self.o.shorten_thunk {
                    self.out.push_str("thunk for ");
                    let last = self.count(n) as isize - 1;
                    self.print(self.child_at(n, last)?, depth + 1, false)?;
                    return Ok(None);
                }
                self.out.push_str("reabstraction thunk ");
                if k == K::ReabstractionThunkHelper {
                    self.out.push_str("helper ");
                }
                let mut i = 0;
                if self.count(n) == 3 {
                    self.print_at(n, 0, depth)?;
                    self.out.push(' ');
                    i = 1;
                }
                self.out.push_str("from ");
                self.print_at(n, i + 1, depth)?;
                self.out.push_str(" to ");
                self.print_at(n, i, depth)?;
            }
            K::ReabstractionThunkHelperWithSelf => {
                self.out.push_str("reabstraction thunk ");
                let mut i = 0;
                if self.count(n) == 4 {
                    self.print_at(n, 0, depth)?;
                    self.out.push(' ');
                    i = 1;
                }
                self.out.push_str("from ");
                self.print_at(n, i + 2, depth)?;
                self.out.push_str(" to ");
                self.print_at(n, i + 1, depth)?;
                self.out.push_str(" self ");
                self.print_at(n, i, depth)?;
            }
            K::ReabstractionThunkHelperWithGlobalActor => {
                self.print_at(n, 0, depth)?;
                self.out.push_str(" with global actor constraint ");
                self.print_at(n, 1, depth)?;
            }
            K::ObjCAsyncCompletionHandlerImpl | K::PredefinedObjCAsyncCompletionHandlerImpl => {
                if k == K::PredefinedObjCAsyncCompletionHandlerImpl {
                    self.out.push_str("checked ");
                }
                self.out.push_str("@objc completion handler block implementation for ");
                if self.count(n) >= 4 {
                    self.print_at(n, 3, depth)?;
                }
                self.print_at(n, 0, depth)?;
                self.out.push_str(" with result type ");
                self.print_at(n, 1, depth)?;
                match self.index(self.child(n, 2)?) {
                    Some(0) => {}
                    Some(1) => self.out.push_str(" nonzero on error"),
                    Some(2) => self.out.push_str(" zero on error"),
                    _ => self.out.push_str(" <invalid error flag>"),
                }
            }
            K::GlobalVariableOnceToken | K::GlobalVariableOnceFunction => {
                self.out.push_str(if k == K::GlobalVariableOnceToken { "one-time initialization token for " } else { "one-time initialization function for " });
                self.print_at(n, 1, depth)?;
            }
            K::GlobalVariableOnceDeclList => {
                if self.count(n) == 1 {
                    self.print_at(n, 0, depth)?;
                } else {
                    self.out.push('(');
                    self.print_children(n, depth, ", ")?;
                    self.out.push(')');
                }
            }
            K::FieldOffset => {
                self.print_at(n, 0, depth)?;
                self.out.push_str("field offset for ");
                self.print_at(n, 1, depth)?;
            }
            K::Directness => self.out.push_str(if self.index(n) == Some(0) { "direct " } else { "indirect " }),
            K::ValueWitness => {
                self.out.push_str(self.text(self.child(n, 0)?));
                self.out.push_str(if self.o.shorten_value_witness { " for " } else { " value witness for " });
                self.print_at(n, 1, depth)?;
            }
            K::FunctionSignatureSpecialization => self.print_specialization_prefix(n, "function signature specialization", depth)?,
            K::GenericPartialSpecialization => self.print_specialization_prefix(n, "partial generic specialization", depth)?,
            K::GenericPartialSpecializationNotReAbstracted => self.print_specialization_prefix(n, "partial generic specialization <not re-abstracted>", depth)?,
            K::GenericSpecialization | K::GenericSpecializationInResilienceDomain => self.print_specialization_prefix(n, "generic specialization", depth)?,
            K::GenericSpecializationPrespecialized => self.print_specialization_prefix(n, "generic pre-specialization", depth)?,
            K::GenericSpecializationNotReAbstracted => self.print_specialization_prefix(n, "generic not re-abstracted specialization", depth)?,
            K::InlinedGenericFunction => self.print_specialization_prefix(n, "inlined generic function", depth)?,
            K::GenericSpecializationParam => {
                self.print_at(n, 0, depth)?;
                for i in 1..self.count(n) {
                    self.out.push_str(if i == 1 { " with " } else { " and " });
                    self.print_at(n, i, depth)?;
                }
            }
            K::FunctionSignatureSpecializationParam | K::FunctionSignatureSpecializationReturn => self.print_function_sig_specialization_params(n, depth)?,
            K::FunctionSignatureSpecializationParamKind => self.print_fss_kind(self.index(n))?,
            K::ProtocolConformance => {
                if self.count(n) == 4 {
                    self.out.push_str("property behavior storage of ");
                    self.print_at(n, 2, depth)?;
                    self.out.push_str(" in ");
                    self.print_at(n, 0, depth)?;
                    self.out.push_str(" : ");
                    self.print_at(n, 1, depth)?;
                } else {
                    self.print_at(n, 0, depth)?;
                    if self.o.display_protocol_conformances {
                        self.out.push_str(" : ");
                        self.print_at(n, 1, depth)?;
                        self.out.push_str(" in ");
                        self.print_at(n, 2, depth)?;
                    }
                }
            }
            K::TypeList => self.print_children(n, depth, "")?,
            K::LabelList => {}
            K::BoundGenericClass | K::BoundGenericStructure | K::BoundGenericEnum | K::BoundGenericProtocol | K::BoundGenericOtherNominalType | K::BoundGenericTypeAlias => {
                self.print_bound_generic(n, depth)?
            }
            K::DynamicSelf => self.out.push_str("Self"),
            K::ErrorType => self.out.push_str("<ERROR TYPE>"),
            K::Metatype => {
                let mut i = 0;
                if self.count(n) == 2 {
                    self.print_at(n, 0, depth)?;
                    self.out.push(' ');
                    i = 1;
                }
                let t = self.child(self.child(n, i)?, 0)?;
                self.print_with_parens(t, depth)?;
                self.out.push_str(if is_existential(self.kind(t)) { ".Protocol" } else { ".Type" });
            }
            K::ExistentialMetatype => {
                let mut i = 0;
                if self.count(n) == 2 {
                    self.print_at(n, 0, depth)?;
                    self.out.push(' ');
                    i = 1;
                }
                self.print_at(n, i, depth)?;
                self.out.push_str(".Type");
            }
            K::ProtocolList => {
                let list = self.child(n, 0)?;
                if self.count(list) == 0 {
                    self.out.push_str("Any");
                } else {
                    self.print_children(list, depth, " & ")?;
                }
            }
            K::ProtocolListWithClass => {
                self.print_at(n, 1, depth)?;
                self.out.push_str(" & ");
                let list = self.child(self.child(n, 0)?, 0)?;
                self.print_children(list, depth, " & ")?;
            }
            K::ProtocolListWithAnyObject => {
                let list = self.child(self.child(n, 0)?, 0)?;
                if self.count(list) > 0 {
                    self.print_children(list, depth, " & ")?;
                    self.out.push_str(" & ");
                }
                self.out.push_str("Swift.AnyObject");
            }
            K::AssociatedTypeRef => {
                self.print_at(n, 0, depth)?;
                self.out.push('.');
                self.out.push_str(self.text(self.child(n, 1)?));
            }
            K::DependentMemberType => {
                self.print_at(n, 0, depth)?;
                self.out.push('.');
                self.print_at(n, 1, depth)?;
            }
            K::DependentAssociatedTypeRef => {
                if self.count(n) > 1 {
                    self.print_at(n, 1, depth)?;
                    self.out.push('.');
                }
                self.print_at(n, 0, depth)?;
            }
            K::DependentGenericParamType => {
                let d = self.index(self.child(n, 0)?).unwrap_or(0);
                let i = self.index(self.child(n, 1)?).unwrap_or(0);
                generic_parameter_name(&mut self.out, d, i);
            }
            K::DependentGenericType => {
                self.print_at(n, 0, depth)?;
                let t = self.child(n, 1)?;
                if self.need_space_before_type(t)? {
                    self.out.push(' ');
                }
                self.print(t, depth + 1, false)?;
            }
            K::DependentGenericSignature | K::DependentPseudogenericSignature => self.print_generic_signature(n, depth)?,
            K::DependentGenericConformanceRequirement => {
                self.print_at(n, 0, depth)?;
                self.out.push_str(": ");
                self.print_at(n, 1, depth)?;
            }
            K::DependentGenericInverseConformanceRequirement => {
                self.print_at(n, 0, depth)?;
                self.out.push_str(": ~");
                match self.index(self.child(n, 1)?) {
                    Some(0) => self.out.push_str("Swift.Copyable"),
                    Some(1) => self.out.push_str("Swift.Escapable"),
                    i => {
                        self.out.push_str("Swift.<bit ");
                        self.push_index(i);
                        self.out.push('>');
                    }
                }
            }
            K::DependentGenericLayoutRequirement => {
                self.print_at(n, 0, depth)?;
                self.out.push_str(": ");
                let name = match self.text(self.child(n, 1)?) {
                    "U" => "_UnknownLayout",
                    "R" => "_RefCountedObject",
                    "N" => "_NativeRefCountedObject",
                    "C" => "AnyObject",
                    "D" => "_NativeClass",
                    "T" | "E" | "e" => "_Trivial",
                    "M" | "m" => "_TrivialAtMost",
                    "S" => "_TrivialStride",
                    "B" => "_BridgeObject",
                    _ => "",
                };
                self.out.push_str(name);
                if self.count(n) > 2 {
                    self.out.push('(');
                    self.print_at(n, 2, depth)?;
                    if self.count(n) > 3 {
                        self.out.push_str(", ");
                        self.print_at(n, 3, depth)?;
                    }
                    self.out.push(')');
                }
            }
            K::DependentGenericSameTypeRequirement => {
                self.print_at(n, 0, depth)?;
                self.out.push_str(" == ");
                self.print_at(n, 1, depth)?;
            }
            K::DependentGenericSameShapeRequirement => {
                self.print_at(n, 0, depth)?;
                self.out.push_str(".shape == ");
                self.print_at(n, 1, depth)?;
                self.out.push_str(".shape");
            }
            K::DependentGenericParamPackMarker | K::DependentGenericParamValueMarker => {}
            K::ThrowsAnnotation => self.out.push_str(" throws"),
            K::TypedThrowsAnnotation => {
                self.out.push_str(" throws(");
                if self.count(n) == 1 {
                    self.print_at(n, 0, depth)?;
                }
                self.out.push(')');
            }
            K::AsyncAnnotation => self.out.push_str(" async"),
            K::ConcurrentFunctionType => self.out.push_str("@Sendable "),
            K::IsolatedAnyFunctionType => self.out.push_str("@isolated(any) "),
            K::NonIsolatedCallerFunctionType => self.out.push_str("nonisolated(nonsending) "),
            K::SendingResultFunctionType => self.out.push_str("sending "),
            K::GlobalActorFunctionType => {
                if self.count(n) > 0 {
                    self.out.push('@');
                    self.print_at(n, 0, depth)?;
                    self.out.push(' ');
                }
            }
            K::OpaqueReturnType => self.out.push_str("some"),
            K::Pack => {
                self.out.push_str("Pack{");
                self.print_children(n, depth, ", ")?;
                self.out.push('}');
            }
            K::PackExpansion => {
                self.out.push_str("repeat ");
                self.print_at(n, 0, depth)?;
            }
            K::OpaqueReturnTypeOf => {
                self.out.push_str("<<opaque return type of ");
                self.print_children(n, depth, "")?;
                self.out.push_str(">>");
            }
            K::OpaqueType => {
                self.print_at(n, 0, depth)?;
                self.out.push('.');
                self.print_at(n, 1, depth)?;
            }
            K::ConstrainedExistential => {
                self.out.push_str("any ");
                self.print_at(n, 0, depth)?;
                self.out.push('<');
                self.print_at(n, 1, depth)?;
                self.out.push('>');
            }
            K::ConstrainedExistentialRequirementList => self.print_children(n, depth, ", ")?,
            K::ConstrainedExistentialSelf => self.out.push_str("Self"),
            K::SugaredOptional => {
                self.print_with_parens(self.child(n, 0)?, depth)?;
                self.out.push('?');
            }
            K::SugaredArray => {
                self.out.push('[');
                self.print_at(n, 0, depth)?;
                self.out.push(']');
            }
            K::SugaredDictionary => {
                self.out.push('[');
                self.print_at(n, 0, depth)?;
                self.out.push_str(" : ");
                self.print_at(n, 1, depth)?;
                self.out.push(']');
            }
            K::SugaredParen => {
                self.out.push('(');
                self.print_at(n, 0, depth)?;
                self.out.push(')');
            }
            K::SILBoxTypeWithLayout => {
                let layout = self.child(n, 0)?;
                let mut args: N = None;
                if self.count(n) == 3 {
                    self.print_at(n, 1, depth)?;
                    self.out.push(' ');
                    args = Some(self.child(n, 2)?);
                }
                self.print(layout, depth + 1, false)?;
                if let Some(args) = args {
                    self.out.push_str(" <");
                    self.print_children(args, depth, ", ")?;
                    self.out.push('>');
                }
            }
            K::SILBoxLayout => {
                self.out.push('{');
                for i in 0..self.count(n) {
                    if i > 0 {
                        self.out.push(',');
                    }
                    self.out.push(' ');
                    self.print_at(n, i, depth)?;
                }
                self.out.push_str(" }");
            }
            K::SILBoxImmutableField | K::SILBoxMutableField => {
                self.out.push_str(if k == K::SILBoxImmutableField { "let " } else { "var " });
                self.print_at(n, 0, depth)?;
            }
            K::ImplFunctionType => self.print_impl_function_type(n, depth)?,
            K::ImplYield | K::ImplParameter | K::ImplResult | K::ImplErrorResult => {
                if k == K::ImplYield {
                    self.out.push_str("@yields ");
                }
                if k == K::ImplErrorResult {
                    self.out.push_str("@error ");
                }
                let count = self.count(n);
                for i in 0..count {
                    self.print_at(n, i, depth)?;
                    if i + 1 < count {
                        self.out.push(' ');
                    }
                }
            }
            K::ImplConvention
            | K::ImplFunctionAttribute
            | K::ImplCoroutineKind
            | K::ImplParameterResultDifferentiability
            | K::ImplParameterSending
            | K::ImplParameterIsolated
            | K::ImplParameterImplicitLeading
            | K::ImplFunctionConventionName => self.out.push_str(self.text(n)),
            K::ImplEscaping => self.out.push_str("@escaping"),
            K::ImplErasedIsolation => self.out.push_str("@isolated(any)"),
            K::ImplSendingResult => self.out.push_str("sending"),
            K::ImplFunctionConvention => {
                self.out.push_str("@convention(");
                self.print_at(n, 0, depth)?;
                if self.count(n) > 1 {
                    self.out.push_str(", mangledCType: \"");
                    self.print_at(n, 1, depth)?;
                    self.out.push('"');
                }
                self.out.push(')');
            }
            K::ImplDifferentiabilityKind => self.out.push_str(match self.text(n) {
                "d" => "@differentiable",
                "l" => "@differentiable(_linear)",
                "f" => "@differentiable(_forward)",
                "r" => "@differentiable(reverse)",
                _ => "",
            }),
            K::AccessorAttachedMacroExpansion
            | K::MemberAttributeAttachedMacroExpansion
            | K::MemberAttachedMacroExpansion
            | K::PeerAttachedMacroExpansion
            | K::ConformanceAttachedMacroExpansion
            | K::ExtensionAttachedMacroExpansion
            | K::BodyAttachedMacroExpansion
            | K::PreambleAttachedMacroExpansion => return self.print_attached_macro(n, depth, as_prefix),
            K::FreestandingMacroExpansion => {
                let index = self.index(self.child(n, 2)?).map_or(-1, |i| i + 1);
                return self.print_entity(n, depth, as_prefix, TypePrinting::None, true, "freestanding macro expansion #", index, "");
            }
            K::MacroExpansionUniqueName => {
                let index = self.index(self.child(n, 2)?).map_or(-1, |i| i + 1);
                return self.print_entity(n, depth, as_prefix, TypePrinting::None, true, "unique name #", index, "");
            }
            _ => return Err(Bad),
        }
        Ok(None)
    }

    /// A child by an index that may have run below zero (JavaScript's `children[-1]` is undefined).
    fn child_at(&self, n: NodeId, i: isize) -> R<NodeId> {
        if i < 0 {
            return Err(Bad);
        }
        self.child(n, i as usize)
    }

    fn push_unless_shortened(&mut self, text: &str) {
        if !self.o.shorten_thunk {
            self.out.push_str(text);
        }
    }

    /// `String(index)`.
    fn push_index(&mut self, i: Option<i64>) {
        match i {
            Some(i) => self.out.push_str(&i.to_string()),
            None => self.out.push_str("undefined"),
        }
    }

    /// `${index + 1}`.
    fn push_plus_one(&mut self, i: Option<i64>) {
        match i {
            Some(i) => self.out.push_str(&(i + 1).to_string()),
            None => self.out.push_str("NaN"),
        }
    }

    /// `<before><child a><middle><child b>`.
    fn print_pair(&mut self, n: NodeId, before: &str, a: usize, middle: &str, b: usize, depth: u32) -> R<()> {
        self.out.push_str(before);
        self.print_at(n, a, depth)?;
        self.out.push_str(middle);
        self.print_at(n, b, depth)
    }

    #[inline(never)]
    fn print_attached_macro(&mut self, n: NodeId, depth: u32, as_prefix: bool) -> R<N> {
        let word = match self.kind(n) {
            K::AccessorAttachedMacroExpansion => "accessor",
            K::MemberAttributeAttachedMacroExpansion => "member attribute",
            K::MemberAttachedMacroExpansion => "member",
            K::PeerAttachedMacroExpansion => "peer",
            K::ConformanceAttachedMacroExpansion => "conformance",
            K::ExtensionAttachedMacroExpansion => "extension",
            K::BodyAttachedMacroExpansion => "body",
            _ => "preamble",
        };
        let mut name = Printer::new(self.t, self.o);
        name.nested = self.nested;
        name.print(self.child(n, 2)?, 0, false)?;
        let extra = format!("{word} macro @{} expansion #", name.out);
        let index = self.index(self.child(n, 3)?).map_or(-1, |i| i + 1);
        self.print_entity(n, depth, as_prefix, TypePrinting::None, true, &extra, index, "")
    }

    fn print_abstract_storage(&mut self, n: NodeId, depth: u32, as_prefix: bool, extra: &str) -> R<N> {
        match self.kind(n) {
            K::Variable => self.print_entity(n, depth, as_prefix, TypePrinting::Colon, true, extra, -1, ""),
            K::Subscript => self.print_entity(n, depth, as_prefix, TypePrinting::Colon, false, extra, -1, "subscript"),
            _ => Err(Bad),
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn print_entity(
        &mut self,
        mut entity: NodeId,
        depth: u32,
        as_prefix: bool,
        mut type_pr: TypePrinting,
        has_name: bool,
        extra_name: &str,
        extra_index: i64,
        overwrite_name: &str,
    ) -> R<N> {
        let mut extra_name = extra_name;
        let mut extra_index = extra_index;
        let mut generic_function_type_list: N = None;
        if self.kind(entity) == K::BoundGenericFunction {
            generic_function_type_list = Some(self.child(entity, 1)?);
            entity = self.first(entity)?;
        }
        let mut multi_word_name = extra_name.contains(' ');
        let local_name = has_name && self.kind(self.child(entity, 1)?) == K::LocalDeclName;
        if local_name {
            multi_word_name = true;
        }
        if as_prefix && (type_pr != TypePrinting::None || multi_word_name) {
            return Ok(Some(entity));
        }

        // The context is printed before the name (`Counter.increment`), or after it when the name
        // has words of its own (`closure #1 in Counter.increment`); modules count as contexts too.
        let mut postfix_context: N;
        let ctx = self.child(entity, 0)?;
        if multi_word_name {
            postfix_context = Some(ctx);
        } else {
            let at = self.out.len();
            postfix_context = self.print(ctx, depth + 1, true)?;
            if self.out.len() != at {
                self.out.push('.');
            }
        }
        if has_name || !overwrite_name.is_empty() {
            if !extra_name.is_empty() && multi_word_name {
                self.out.push_str(extra_name);
                if extra_index >= 0 {
                    self.out.push_str(&extra_index.to_string());
                }
                self.out.push_str(" of ");
                extra_name = "";
                extra_index = -1;
            }
            let at = self.out.len();
            if !overwrite_name.is_empty() {
                self.out.push_str(overwrite_name);
            } else {
                let name = self.child(entity, 1)?;
                if self.kind(name) != K::PrivateDeclName {
                    self.print(name, depth + 1, false)?;
                }
                if let Some(private_name) = self.find(entity, K::PrivateDeclName) {
                    self.print(private_name, depth + 1, false)?;
                }
            }
            if self.out.len() != at && !extra_name.is_empty() {
                self.out.push('.');
            }
        }
        if !extra_name.is_empty() {
            self.out.push_str(extra_name);
            if extra_index >= 0 {
                self.out.push_str(&extra_index.to_string());
            }
        }
        if type_pr != TypePrinting::None {
            let type_node = self.find(entity, K::Type).ok_or(Bad)?;
            let t = self.child(type_node, 0)?;
            if type_pr == TypePrinting::Function {
                let mut f = t;
                while self.kind(f) == K::DependentGenericType {
                    f = self.child(self.child(f, 1)?, 0)?;
                }
                if !matches!(self.kind(f), K::FunctionType | K::NoEscapeFunctionType | K::UncurriedFunctionType | K::CFunctionPointer | K::ThinFunctionType) {
                    type_pr = TypePrinting::Colon;
                }
            }
            if type_pr == TypePrinting::Colon {
                if self.o.display_entity_types {
                    self.out.push_str(" : ");
                    self.print_entity_type(entity, t, generic_function_type_list, depth)?;
                }
            } else {
                if multi_word_name || self.need_space_before_type(t)? {
                    self.out.push(' ');
                }
                self.print_entity_type(entity, t, generic_function_type_list, depth)?;
            }
        }
        if !as_prefix {
            if let Some(context) = postfix_context {
                let of = matches!(
                    self.kind(entity),
                    K::DefaultArgumentInitializer
                        | K::Initializer
                        | K::PropertyWrapperBackingInitializer
                        | K::PropertyWrapperInitFromProjectedValue
                        | K::PropertyWrappedFieldInitAccessor
                );
                self.out.push_str(if of { " of " } else { " in " });
                self.print(context, depth + 1, false)?;
                postfix_context = None;
            }
        }
        Ok(postfix_context)
    }

    fn print_entity_type(&mut self, entity: NodeId, t: NodeId, generic_function_type_list: N, depth: u32) -> R<()> {
        let labels = self.find(entity, K::LabelList);
        if labels.is_some() || generic_function_type_list.is_some() {
            let mut t = t;
            if let Some(list) = generic_function_type_list {
                self.out.push('<');
                self.print_children(list, depth, ", ")?;
                self.out.push('>');
            }
            if self.kind(t) == K::DependentGenericType {
                if generic_function_type_list.is_none() {
                    self.print_at(t, 0, depth)?;
                }
                let dependent = self.child(t, 1)?;
                if self.need_space_before_type(dependent)? {
                    self.out.push(' ');
                }
                t = self.first(dependent)?;
            }
            self.print_function_type(labels, t, depth)
        } else {
            self.print(t, depth + 1, false)?;
            Ok(())
        }
    }

    #[inline(never)]
    fn print_function_type(&mut self, labels: N, n: NodeId, depth: u32) -> R<()> {
        if self.count(n) < 2 {
            return Err(Bad);
        }
        let convention = |p: &mut Self, name: &str| -> R<()> {
            p.out.push_str("@convention(");
            p.out.push_str(name);
            let first = p.first(n)?;
            if p.kind(first) == K::ClangType {
                p.out.push_str(", mangledCType: \"");
                p.print(first, depth + 1, false)?;
                p.out.push('"');
            }
            p.out.push_str(") ");
            Ok(())
        };
        match self.kind(n) {
            K::FunctionType | K::UncurriedFunctionType | K::NoEscapeFunctionType => {}
            K::AutoClosureType | K::EscapingAutoClosureType => self.out.push_str("@autoclosure "),
            K::ThinFunctionType => self.out.push_str("@convention(thin) "),
            K::CFunctionPointer => convention(self, "c")?,
            K::EscapingObjCBlock => {
                self.out.push_str("@escaping ");
                convention(self, "block")?;
            }
            K::ObjCBlock => convention(self, "block")?,
            _ => return Err(Bad),
        }
        let children = self.children(n);
        let t = self.t;
        let has = |kind: Kind| children.iter().copied().find(|&c| t.kind(c) == kind);
        let isolation = children.iter().copied().find(|&c| matches!(t.kind(c), K::IsolatedAnyFunctionType | K::GlobalActorFunctionType | K::NonIsolatedCallerFunctionType));
        let diff = has(K::DifferentiableFunctionType);
        let thrown = children.iter().copied().find(|&c| matches!(t.kind(c), K::ThrowsAnnotation | K::TypedThrowsAnnotation));
        let concurrent = has(K::ConcurrentFunctionType).is_some();
        let is_async = has(K::AsyncAnnotation).is_some();
        let sending = has(K::SendingResultFunctionType).is_some();
        if let Some(isolation) = isolation {
            self.print(isolation, depth + 1, false)?;
        }
        if let Some(diff) = diff {
            self.out.push_str(match self.index(diff).and_then(|i| u8::try_from(i).ok()) {
                Some(b'f') => "@differentiable(_forward) ",
                Some(b'r') => "@differentiable(reverse) ",
                Some(b'l') => "@differentiable(_linear) ",
                Some(b'd') => "@differentiable ",
                _ => "",
            });
        }
        if concurrent {
            self.out.push_str("@Sendable ");
        }
        let count = self.count(n);
        let args = self.child(n, count - 2)?;
        self.print_function_parameters(labels, args, depth, self.o.show_function_argument_types)?;
        if !self.o.show_function_argument_types {
            return Ok(());
        }
        if is_async {
            self.out.push_str(" async");
        }
        if let Some(thrown) = thrown {
            self.print(thrown, depth + 1, false)?;
        }
        self.out.push_str(" -> ");
        if sending {
            self.out.push_str("sending ");
        }
        self.print_at(n, count - 1, depth)
    }

    #[inline(never)]
    fn print_function_parameters(&mut self, labels: N, args: NodeId, depth: u32, show_types: bool) -> R<()> {
        if self.kind(args) != K::ArgumentTuple {
            return Err(Bad);
        }
        let params = self.first(self.first(args)?)?;
        if self.kind(params) != K::Tuple {
            if show_types {
                self.out.push('(');
                self.print(params, depth + 1, false)?;
                self.out.push(')');
            } else {
                self.out.push_str("(_:)");
            }
            return Ok(());
        }
        let has_labels = labels.is_some_and(|l| self.count(l) > 0);
        self.out.push('(');
        for (i, &param) in self.children(params).iter().enumerate() {
            if i > 0 && show_types {
                self.out.push_str(", ");
            }
            if has_labels {
                let label = self.child(labels.unwrap(), i)?;
                self.out.push_str(if self.kind(label) == K::Identifier { self.text(label) } else { "_" });
                self.out.push(':');
            } else if !show_types {
                match self.find(param, K::TupleElementName) {
                    Some(label) => {
                        self.out.push_str(self.text(label));
                        self.out.push(':');
                    }
                    None => self.out.push_str("_:"),
                }
            }
            if has_labels && show_types {
                self.out.push(' ');
            }
            if show_types {
                self.print(param, depth + 1, false)?;
            }
        }
        self.out.push(')');
        Ok(())
    }

    fn find_sugar(&self, n: NodeId) -> R<Sugar> {
        if self.count(n) == 1 && self.kind(n) == K::Type {
            return self.find_sugar(self.first(n)?);
        }
        let k = self.kind(n);
        if self.count(n) != 2 || (k != K::BoundGenericEnum && k != K::BoundGenericStructure) {
            return Ok(Sugar::None);
        }
        let unbound = self.first(self.child(n, 0)?)?;
        let args = self.child(n, 1)?;
        if self.count(unbound) < 2 {
            return Ok(Sugar::None);
        }
        let module = self.child(unbound, 0)?;
        let is_swift = self.kind(module) == K::Module && self.t.text(module) == Some("Swift");
        let name_node = self.child(unbound, 1)?;
        let name = if self.kind(name_node) == K::Identifier { self.t.text(name_node) } else { None };
        if !is_swift {
            return Ok(Sugar::None);
        }
        let arity = self.count(args);
        if k == K::BoundGenericEnum {
            return Ok(match name {
                Some("Optional") if arity == 1 => Sugar::Optional,
                Some("ImplicitlyUnwrappedOptional") if arity == 1 => Sugar::Implicit,
                _ => Sugar::None,
            });
        }
        Ok(match name {
            Some("Array") if arity == 1 => Sugar::Array,
            Some("Dictionary") if arity == 2 => Sugar::Dictionary,
            _ => Sugar::None,
        })
    }

    #[inline(never)]
    fn print_bound_generic(&mut self, n: NodeId, depth: u32) -> R<()> {
        if self.count(n) < 2 {
            return Ok(());
        }
        if self.count(n) != 2 || !self.o.synthesize_sugar_on_types || self.kind(n) == K::BoundGenericClass {
            return self.print_bound_generic_no_sugar(n, depth);
        }
        if self.kind(n) == K::BoundGenericProtocol {
            self.print_children(self.child(n, 1)?, depth, "")?;
            self.out.push_str(" as ");
            return self.print_at(n, 0, depth);
        }
        let sugar = self.find_sugar(n)?;
        let args = self.child(n, 1)?;
        match sugar {
            Sugar::Optional | Sugar::Implicit => {
                self.print_with_parens(self.child(args, 0)?, depth)?;
                self.out.push(if sugar == Sugar::Optional { '?' } else { '!' });
            }
            Sugar::Array => {
                self.out.push('[');
                self.print_at(args, 0, depth)?;
                self.out.push(']');
            }
            Sugar::Dictionary => {
                self.out.push('[');
                self.print_at(args, 0, depth)?;
                self.out.push_str(" : ");
                self.print_at(args, 1, depth)?;
                self.out.push(']');
            }
            Sugar::None => self.print_bound_generic_no_sugar(n, depth)?,
        }
        Ok(())
    }

    fn print_bound_generic_no_sugar(&mut self, n: NodeId, depth: u32) -> R<()> {
        self.print_at(n, 0, depth)?;
        self.out.push('<');
        self.print_children(self.child(n, 1)?, depth, ", ")?;
        self.out.push('>');
        Ok(())
    }

    #[inline(never)]
    fn print_generic_signature(&mut self, n: NodeId, depth: u32) -> R<()> {
        self.out.push('<');
        let count = self.count(n);
        let mut num_params = 0;
        while num_params < count && self.kind(self.child(n, num_params)?) == K::DependentGenericParamCount {
            num_params += 1;
        }
        let mut first_requirement = num_params;
        while first_requirement < count {
            let mut c = self.child(n, first_requirement)?;
            if self.kind(c) == K::Type {
                c = self.first(c)?;
            }
            if self.kind(c) != K::DependentGenericParamPackMarker && self.kind(c) != K::DependentGenericParamValueMarker {
                break;
            }
            first_requirement += 1;
        }
        let marker = |p: &Self, kind: Kind, d: i64, i: i64| -> R<N> {
            for r in num_params..first_requirement {
                let c = p.child(n, r)?;
                if p.kind(c) != kind {
                    continue;
                }
                let mut t = p.first(c)?;
                if p.kind(t) != K::Type {
                    continue;
                }
                t = p.first(t)?;
                if p.kind(t) != K::DependentGenericParamType {
                    continue;
                }
                // swift-demangle compares the depth with the index and the index with the depth.
                if p.index(p.child(t, 0)?) == Some(i) && p.index(p.child(t, 1)?) == Some(d) {
                    return Ok(Some(c));
                }
            }
            Ok(None)
        };
        for d in 0..num_params {
            if d > 0 {
                self.out.push_str("><");
            }
            let params = self.index(self.child(n, d)?).unwrap_or(0);
            let mut i = 0i64;
            while i < params {
                if i > 0 {
                    self.out.push_str(", ");
                }
                if i >= 128 {
                    self.out.push_str("...");
                    break;
                }
                if marker(self, K::DependentGenericParamPackMarker, d as i64, i)?.is_some() {
                    self.out.push_str("each ");
                }
                let value = marker(self, K::DependentGenericParamValueMarker, d as i64, i)?;
                if value.is_some() {
                    self.out.push_str("let ");
                }
                generic_parameter_name(&mut self.out, d as i64, i);
                if let Some(value) = value {
                    self.out.push_str(": ");
                    self.print_at(value, 1, depth)?;
                }
                i += 1;
            }
        }
        if first_requirement != count && self.o.display_where_clauses {
            self.out.push_str(" where ");
            for r in first_requirement..count {
                if r > first_requirement {
                    self.out.push_str(", ");
                }
                self.print_at(n, r, depth)?;
            }
        }
        self.out.push('>');
        Ok(())
    }

    #[inline(never)]
    fn print_specialization_prefix(&mut self, n: NodeId, description: &str, depth: u32) -> R<()> {
        if !self.o.display_generic_specializations {
            if !self.specialization_prefix_printed {
                self.out.push_str("specialized ");
                self.specialization_prefix_printed = true;
            }
            return Ok(());
        }
        self.out.push_str(description);
        self.out.push_str(" <");
        let mut separator = "";
        let mut arg_num = 0;
        for &c in self.children(n) {
            match self.kind(c) {
                K::SpecializationPassID | K::DroppedArgument => {}
                K::IsSerialized => {
                    self.out.push_str(separator);
                    separator = ", ";
                    self.print(c, depth + 1, false)?;
                }
                kind => {
                    if self.count(c) > 0 {
                        self.out.push_str(separator);
                        separator = ", ";
                        if kind == K::FunctionSignatureSpecializationParam {
                            self.out.push_str(&format!("Arg[{arg_num}] = "));
                            self.print_function_sig_specialization_params(c, depth)?;
                        } else if kind == K::FunctionSignatureSpecializationReturn {
                            self.out.push_str("Return = ");
                            self.print_function_sig_specialization_params(c, depth)?;
                        } else {
                            self.print(c, depth + 1, false)?;
                        }
                    }
                    arg_num += 1;
                }
            }
        }
        self.out.push_str("> of ");
        Ok(())
    }

    #[inline(never)]
    fn print_function_sig_specialization_params(&mut self, n: NodeId, depth: u32) -> R<()> {
        let count = self.count(n);
        let mut i = 0;
        while i < count {
            let kind = self.index(self.child(n, i)?);
            match kind {
                Some(fss::BOX_TO_VALUE | fss::BOX_TO_STACK | fss::IN_OUT_TO_OUT) => {
                    self.print_at(n, i, depth)?;
                    i += 1;
                }
                Some(fss::CONSTANT_PROP_FUNCTION | fss::CONSTANT_PROP_GLOBAL) => {
                    self.out.push('[');
                    self.print_at(n, i, depth)?;
                    i += 1;
                    self.out.push_str(" : ");
                    let text = self.text(self.child(n, i)?);
                    i += 1;
                    // Printed as the runtime's demangler prints a name by default: without the sugar.
                    match parse_swift(text) {
                        Some(tree) => {
                            // Each name inside another starts the depth anew; the TypeScript went on until
                            // JavaScript's stack ran out. Names nest a level or two; past this they fail.
                            if self.nested >= MAX_NESTED_NAMES {
                                return Err(Bad);
                            }
                            let mut inner = Printer::new(&tree, Options { synthesize_sugar_on_types: false, ..FULL });
                            inner.nested = self.nested + 1;
                            inner.print(tree.root, 0, false)?;
                            self.out.push_str(&inner.out);
                        }
                        None => self.out.push_str(text),
                    }
                    self.out.push(']');
                }
                Some(fss::CONSTANT_PROP_INTEGER | fss::CONSTANT_PROP_FLOAT) => {
                    self.out.push('[');
                    self.print_at(n, i, depth)?;
                    self.out.push_str(" : ");
                    self.print_at(n, i + 1, depth)?;
                    i += 2;
                    self.out.push(']');
                }
                Some(fss::CONSTANT_PROP_STRING) => {
                    self.out.push('[');
                    self.print_at(n, i, depth)?;
                    self.out.push_str(" : ");
                    self.print_at(n, i + 1, depth)?;
                    self.out.push('\'');
                    self.print_at(n, i + 2, depth)?;
                    i += 3;
                    self.out.push_str("']");
                }
                Some(fss::CONSTANT_PROP_KEY_PATH) => {
                    self.out.push('[');
                    self.print_at(n, i, depth)?;
                    self.out.push_str(" : ");
                    self.print_at(n, i + 1, depth)?;
                    self.out.push('<');
                    self.print_at(n, i + 2, depth)?;
                    self.out.push(',');
                    self.print_at(n, i + 3, depth)?;
                    i += 4;
                    self.out.push_str(">]");
                }
                Some(fss::CLOSURE_PROP | fss::CLOSURE_PROP_PREVIOUS_ARG | fss::CLOSURE_PROP_ESCAPING) => {
                    self.out.push('[');
                    self.print_at(n, i, depth)?;
                    self.out.push_str(" : ");
                    self.print_at(n, i + 1, depth)?;
                    i += 2;
                    self.out.push_str(", Argument Types : [");
                    while i < count {
                        let c = self.child(n, i)?;
                        if self.kind(c) != K::Type {
                            break;
                        }
                        self.print(c, depth + 1, false)?;
                        i += 1;
                        if i < count && self.t.text(self.child(n, i)?).is_some() {
                            self.out.push_str(", ");
                        }
                    }
                    self.out.push(']');
                }
                _ => {
                    self.print_at(n, i, depth)?;
                    i += 1;
                }
            }
        }
        Ok(())
    }

    fn print_fss_kind(&mut self, raw: Option<i64>) -> R<()> {
        let raw = raw.ok_or(Bad)?;
        let mut options: Vec<&str> = Vec::new();
        if raw & fss::EXISTENTIAL_TO_GENERIC != 0 {
            options.push("Existential To Protocol Constrained Generic");
        }
        if raw & fss::DEAD != 0 {
            options.push("Dead");
        }
        if raw & fss::OWNED_TO_GUARANTEED != 0 {
            options.push("Owned To Guaranteed");
        }
        if raw & fss::GUARANTEED_TO_OWNED != 0 {
            options.push("Guaranteed To Owned");
        }
        if raw & fss::SROA != 0 {
            options.push("Exploded");
        }
        if !options.is_empty() {
            self.out.push_str(&options.join(" and "));
            return Ok(());
        }
        self.out.push_str(match raw {
            fss::BOX_TO_VALUE => "Value Promoted from Box",
            fss::BOX_TO_STACK => "Stack Promoted from Box",
            fss::IN_OUT_TO_OUT => "InOut Converted to Out",
            fss::CONSTANT_PROP_FUNCTION => "Constant Propagated Function",
            fss::CONSTANT_PROP_GLOBAL => "Constant Propagated Global",
            fss::CONSTANT_PROP_INTEGER => "Constant Propagated Integer",
            fss::CONSTANT_PROP_FLOAT => "Constant Propagated Float",
            fss::CONSTANT_PROP_STRING => "Constant Propagated String",
            fss::CONSTANT_PROP_KEY_PATH => "Constant Propagated KeyPath",
            fss::CLOSURE_PROP => "Closure Propagated",
            fss::CLOSURE_PROP_PREVIOUS_ARG => "Closure Propagated : Previous Argument",
            fss::CLOSURE_PROP_ESCAPING => "Escaping Closure Propagated",
            _ => return Err(Bad),
        });
        Ok(())
    }

    #[inline(never)]
    fn print_impl_function_type(&mut self, fun: NodeId, depth: u32) -> R<()> {
        let mut pattern_subs: N = None;
        let mut invocation_subs: N = None;
        let mut sending_result: N = None;
        let mut state = 0;
        let transition = |p: &mut Self, state: &mut i32, to: i32, pattern_subs: N, sending_result: N| -> R<()> {
            while *state < to {
                if *state == 0 {
                    if let Some(subs) = pattern_subs {
                        p.out.push_str("@substituted ");
                        p.print_at(subs, 0, depth)?;
                        p.out.push(' ');
                    }
                    p.out.push('(');
                } else {
                    p.out.push_str(") -> ");
                    if let Some(sending) = sending_result {
                        p.print(sending, depth + 1, false)?;
                        p.out.push(' ');
                    }
                    p.out.push('(');
                }
                *state += 1;
            }
            Ok(())
        };
        for &c in self.children(fun) {
            match self.kind(c) {
                K::ImplParameter => {
                    if state == 1 {
                        self.out.push_str(", ");
                    }
                    transition(self, &mut state, 1, pattern_subs, sending_result)?;
                    self.print(c, depth + 1, false)?;
                }
                K::ImplResult | K::ImplYield | K::ImplErrorResult => {
                    if state == 2 {
                        self.out.push_str(", ");
                    }
                    transition(self, &mut state, 2, pattern_subs, sending_result)?;
                    self.print(c, depth + 1, false)?;
                }
                K::ImplPatternSubstitutions => pattern_subs = Some(c),
                K::ImplInvocationSubstitutions => invocation_subs = Some(c),
                K::ImplSendingResult => sending_result = Some(c),
                _ => {
                    self.print(c, depth + 1, false)?;
                    self.out.push(' ');
                }
            }
        }
        transition(self, &mut state, 2, pattern_subs, sending_result)?;
        self.out.push(')');
        // swift-demangle runs the substitutions together, with nothing between them.
        if let Some(subs) = pattern_subs {
            self.out.push_str(" for <");
            self.print_children(self.child(subs, 1)?, depth, "")?;
            self.out.push('>');
        }
        if let Some(subs) = invocation_subs {
            self.out.push_str(" for <");
            self.print_children(self.child(subs, 0)?, depth, "")?;
            self.out.push('>');
        }
        Ok(())
    }
}

/// A Swift symbol demangled, in full and simplified, or None when it is not one
/// or does not parse.
pub fn demangle_swift(symbol: &str) -> Option<(String, String)> {
    let tree = parse_swift(symbol)?;
    let mut full = Printer::new(&tree, FULL);
    full.out.reserve(symbol.len() * 3);
    full.print(tree.root, 0, false).ok()?;
    let mut short = Printer::new(&tree, SIMPLIFIED);
    short.out.reserve(symbol.len());
    short.print(tree.root, 0, false).ok()?;
    Some((full.out, short.out))
}
