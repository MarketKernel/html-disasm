/**
 * The instruction catalogue (src/data/arm64-instructions.json) and the HLA64
 * words (src/data/hla64-words.json), looked up the way the listing needs:
 * `b.ne` finds the `b.cond` entry, `ldaddl` its own.
 *
 * The English files are the source: they hold the structure (forms, syntax,
 * links, categories) and the English text. A translation file beside each
 * (`*.ru.json`) holds only the texts — summary and description of every
 * instruction, the names of the conditions, the description and category of
 * every word — and is laid over the English in the interface language. A
 * text a translation lacks stays English.
 *
 * Every file comes as its text and is parsed the first time it is needed, so
 * a page opened on a WebAssembly module never parses the x86 catalogue.
 */

import arm32Text from '../data/arm32-instructions.json?text';
import arm32RuText from '../data/arm32-instructions.ru.json?text';
import arm64Text from '../data/arm64-instructions.json?text';
import arm64RuText from '../data/arm64-instructions.ru.json?text';
import cilText from '../data/cil-instructions.json?text';
import cilRuText from '../data/cil-instructions.ru.json?text';
import wordsText from '../data/hla64-words.json?text';
import wordsRuText from '../data/hla64-words.ru.json?text';
import jvmText from '../data/jvm-instructions.json?text';
import jvmRuText from '../data/jvm-instructions.ru.json?text';
import wasmText from '../data/wasm-instructions.json?text';
import wasmRuText from '../data/wasm-instructions.ru.json?text';
import x86Text from '../data/x86-instructions.json?text';
import x86RuText from '../data/x86-instructions.ru.json?text';
import { append, type Arch } from './disassembly';
import { language, t, type Language } from './i18n';
import { allOps, IMM, opcodeText, W, type OpInfo } from './wasm/opcodes';
import { allOps as cilOps, F as CIL_F, opcodeText as cilOpcodeText, OPERAND } from './cil/opcodes';
import { allOps as jvmOps, F as JVM_F, opcodeText as jvmOpcodeText, OPERAND as JVM_OPERAND } from './jvm/opcodes';

export interface Form {
  heading: string;
  aliasOf?: string;
  /** AArch32: the instruction sets with an encoding of the form (A32, T32). */
  isa?: string[];
  syntax: string[];
  url: string;
}

export interface Entry {
  summary: string;
  description: string;
  operation: string;
  flags: string;
  category: string;
  group: string;
  forms: Form[];
  /** WebAssembly: what it takes from the stack and pushes (`i32 i32 > i32`). */
  stack?: string;
}

export interface Condition {
  name: string;
  flags: string;
  hla?: string;
  unsigned?: boolean;
  zero?: boolean;
}

export interface Word {
  id: string;
  status: 'hla64' | 'new';
  category: string;
  syntax: string;
  description: string;
  example: string;
  /** The ARM64 instructions the word stands for. */
  instructions: string[];
  /** The views that write it; both when it is absent. */
  targets?: Arch[];
  /** The WebAssembly instructions the word stands for, and an example from the WebAssembly view. */
  wasm?: string[];
  wasmExample?: string;
  /** The x86-64 instructions the word stands for, and an example from the x86-64 view. */
  x86?: string[];
  x86Example?: string;
  /** The CIL instructions the word stands for, and an example from the .NET view. */
  cil?: string[];
  cilExample?: string;
  /** The JVM instructions the word stands for, and an example from the Java view. */
  jvm?: string[];
  jvmExample?: string;
}

/* ------------------------------------------------------------------ *
 * The files, and their texts in the interface language
 * ------------------------------------------------------------------ */

/** A file's JSON, parsed on the first call. */
function parsed<T>(text: string): () => T {
  let value: T | undefined;
  return () => (value ??= JSON.parse(text) as T);
}

interface Texts {
  summary: string;
  description: string;
}
/** A translation of a catalogue: the texts of its instructions. */
type Translations = Partial<Record<Language, () => { instructions: Record<string, Texts> }>>;

/** An entry with the texts of a translation laid over its English ones. */
function withTexts(entry: Entry, texts: Texts | undefined): Entry {
  return texts ? { ...entry, summary: texts.summary || entry.summary, description: texts.description || entry.description } : entry;
}

/** The entry of a key in the interface language, made once per language. */
function localized(make: (key: string, lang: Language) => Entry | undefined): (key: string) => Entry | undefined {
  const made = new Map<string, Entry | undefined>();
  let madeFor: Language | null = null;
  return (key) => {
    const lang = language();
    if (madeFor !== lang) {
      made.clear();
      madeFor = lang;
    }
    if (!made.has(key)) made.set(key, make(key, lang));
    return made.get(key);
  };
}

/** A catalogue whose file holds whole entries (arm64, AArch32, x86): the English ones, and the lookup in the interface language. */
function entriesOf(english: () => { instructions: Record<string, Entry> }, translations: Translations) {
  const lookup = localized((key, lang) => {
    const entry = english().instructions[key];
    return entry && withTexts(entry, translations[lang]?.().instructions[key]);
  });
  return { english: (key: string): Entry | undefined => english().instructions[key], lookup };
}

/** A catalogue whose entries are made from the opcode table and the texts of a file (WebAssembly, CIL, JVM). */
function madeEntries(make: (name: string) => Entry | undefined, translations: Translations): (name: string) => Entry | undefined {
  return localized((name, lang) => {
    const entry = make(name);
    return entry && withTexts(entry, translations[lang]?.().instructions[name]);
  });
}

/* ------------------------------------------------------------------ *
 * arm64 and the HLA64 words
 * ------------------------------------------------------------------ */

const ARM64 = parsed<{ docBase?: string; instructions: Record<string, Entry>; conditions: Record<string, Condition> }>(arm64Text);
const ARM64_TRANSLATIONS: Partial<Record<Language, () => { instructions: Record<string, Texts>; conditions: Record<string, { name: string }> }>> = { ru: parsed(arm64RuText) };
const ARM64_ENTRIES = entriesOf(ARM64, ARM64_TRANSLATIONS);
const WORDS = parsed<{ words: Word[] }>(wordsText);
const WORD_TRANSLATIONS: Partial<Record<Language, () => { words: Record<string, { category: string; description: string }> }>> = { ru: parsed(wordsRuText) };

const DOC_BASE = 'https://developer.arm.com/documentation/ddi0602/latest/';

/** The catalogue key of a printed mnemonic: b.ne → b.cond. */
export function catalogKey(mnemonic: string): string {
  if (/^bc?\.[a-z]{2}$/.test(mnemonic)) return `${mnemonic.split('.')[0]}.cond`;
  return mnemonic;
}

/** The entry of a mnemonic, its texts in the interface language. */
export function lookup(mnemonic: string): Entry | undefined {
  return ARM64_ENTRIES.lookup(catalogKey(mnemonic));
}

/** The English entry, whatever the interface language (for searching in both). */
export function lookupEnglish(mnemonic: string): Entry | undefined {
  return ARM64_ENTRIES.english(catalogKey(mnemonic));
}

/** The sixteen conditions, named in the interface language. */
export function conditions(): Record<string, Condition> {
  const english = ARM64().conditions;
  const names = ARM64_TRANSLATIONS[language()]?.().conditions;
  if (!names) return english;
  return Object.fromEntries(Object.entries(english).map(([key, c]) => [key, { ...c, name: names[key]?.name || c.name }]));
}

/** The condition of b.cond-style mnemonics, if any. */
export function conditionOf(mnemonic: string): string | undefined {
  return /^bc?\.([a-z]{2})$/.exec(mnemonic)?.[1];
}

let wordsMade: { lang: Language; words: Word[]; byId: Map<string, Word> } | undefined;

/** The HLA64 words, described in the interface language. */
export function allWords(): Word[] {
  return wordsIn(language()).words;
}

export function word(id: string): Word | undefined {
  return wordsIn(language()).byId.get(id);
}

function wordsIn(lang: Language) {
  if (wordsMade?.lang !== lang) {
    const texts = WORD_TRANSLATIONS[lang]?.().words;
    const words = texts ? WORDS().words.map((w) => ({ ...w, category: texts[w.id]?.category || w.category, description: texts[w.id]?.description || w.description })) : WORDS().words;
    wordsMade = { lang, words, byId: new Map(words.map((w) => [w.id, w])) };
  }
  return wordsMade;
}

export function allMnemonics(): string[] {
  return Object.keys(ARM64().instructions);
}

export function docUrl(form: Form): string {
  return form.url.startsWith('http') ? form.url : (ARM64().docBase ?? DOC_BASE) + form.url;
}

/* ------------------------------------------------------------------ *
 * WebAssembly
 * ------------------------------------------------------------------ */

interface WasmText {
  summary: string;
  description: string;
  operation: string;
  category: string;
}

const WASM_TEXTS = parsed<{ instructions: Record<string, WasmText> }>(wasmText);
const SPEC = 'https://webassembly.github.io/spec/core/syntax/instructions.html#';
const THREADS = 'https://github.com/WebAssembly/threads/blob/main/proposals/threads/Overview.md';
const LEGACY_EXCEPTIONS = 'https://github.com/WebAssembly/exception-handling/blob/main/proposals/exception-handling/legacy/Exceptions.md';
const WIDE = 'https://github.com/WebAssembly/wide-arithmetic/blob/main/proposals/wide-arithmetic/Overview.md';

function specUrl(op: OpInfo): string {
  if (op.group === 'atomic') return THREADS;
  if (/^(try|catch|catch_all|delegate|rethrow)$/.test(op.name)) return LEGACY_EXCEPTIONS;
  if (/128|mul_wide/.test(op.name)) return WIDE;
  const anchor = op.group === 'exception' ? 'control' : op.group;
  return `${SPEC}${anchor}-instructions`;
}

/** The operands of an instruction in the text format, as a template. */
const IMMEDIATES: Record<number, string> = {
  [IMM.NONE]: '', [IMM.BLOCK]: ' [(type t)] [(param …)] [(result …)]', [IMM.LABEL]: ' label', [IMM.BR_TABLE]: ' label* default',
  [IMM.FUNC]: ' func', [IMM.CALL_INDIRECT]: ' [table] (type t)', [IMM.LOCAL]: ' local', [IMM.GLOBAL]: ' global', [IMM.TABLE]: ' table',
  [IMM.MEMARG]: ' [memory] [offset=n] [align=n]', [IMM.I32]: ' i32', [IMM.I64]: ' i64', [IMM.F32]: ' f32', [IMM.F64]: ' f64',
  [IMM.SELECT_T]: ' (result t)', [IMM.HEAP]: ' heaptype', [IMM.MEM]: ' [memory]', [IMM.MEMORY_INIT]: ' [memory] data', [IMM.DATA]: ' data',
  [IMM.MEMORY_COPY]: ' [memory memory]', [IMM.TABLE_INIT]: ' [table] elem', [IMM.ELEM]: ' elem', [IMM.TABLE_COPY]: ' [table table]',
  [IMM.V128]: ' i32x4 n n n n', [IMM.SHUFFLE]: ' lane×16', [IMM.LANE]: ' lane', [IMM.MEMARG_LANE]: ' [memory] [offset=n] [align=n] lane',
  [IMM.FENCE]: '', [IMM.TRY_TABLE]: ' [blocktype] (catch tag label)*', [IMM.TAG]: ' tag', [IMM.TYPE]: ' type', [IMM.TYPE_FIELD]: ' type field',
  [IMM.TYPE_N]: ' type n', [IMM.TYPE_DATA]: ' type data', [IMM.TYPE_ELEM]: ' type elem', [IMM.TYPE_TYPE]: ' type type',
  [IMM.REF_TEST]: ' (ref ht)', [IMM.REF_TEST_NULL]: ' (ref null ht)', [IMM.BR_ON_CAST]: ' label reftype reftype',
};

const WASM_OPS = new Map<string, OpInfo[]>();
for (const op of allOps()) {
  append(WASM_OPS, op.name, op);
}

function wasmEntry(name: string): Entry | undefined {
  const text = WASM_TEXTS().instructions[name];
  const ops = WASM_OPS.get(name);
  if (!text || !ops) return undefined;
  const op = ops[0]!;
  return {
    summary: text.summary,
    description: text.description,
    operation: text.operation,
    flags: ops.some((o) => o.flags & W.TRAPS) ? 'can trap' : 'none',
    category: text.category,
    group: op.group,
    stack: op.sig ? op.sig.replace('>', '→').replace(/\s+/g, ' ').trim() : undefined,
    forms: ops.map((o) => ({ heading: `${o.name} · ${opcodeText(o.code)}`, syntax: [`${o.name}${IMMEDIATES[o.imm] ?? ''}`], url: specUrl(o) })),
  };
}

/* ------------------------------------------------------------------ *
 * One interface for all
 * ------------------------------------------------------------------ */

/** The instructions of an architecture, as the reference, the statistics and the search use them. */
export interface Catalogue {
  arch: Arch;
  lookup(mnemonic: string): Entry | undefined;
  lookupEnglish(mnemonic: string): Entry | undefined;
  /** The entry a printed mnemonic belongs to: b.ne → b.cond. */
  key(mnemonic: string): string;
  mnemonics(): string[];
  /** The groups the reference lists them under, in order. */
  groups: string[];
  /** The HLA64 words the view of this architecture writes. */
  words(): Word[];
  /** The instructions a word stands for, and an example as this architecture's view writes it. */
  wordInstructions(word: Word): string[];
  wordExample(word: Word): string;
  docUrl(form: Form): string;
}

/** The words of a view: those for every view (no targets) count only for arm64 and WebAssembly. */
const wordsFor = (arch: Arch, everywhere: boolean) => () => allWords().filter((w) => (w.targets ? w.targets.includes(arch) : everywhere));

/* ------------------------------------------------------------------ *
 * AArch32
 * ------------------------------------------------------------------ */

const ARM32 = parsed<{ docBase: string; instructions: Record<string, Entry> }>(arm32Text);
const ARM32_ENTRIES = entriesOf(ARM32, { ru: parsed(arm32RuText) });
const ARM32_CONDITIONS = new Set(['eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'cs', 'cc', 'al']);

/**
 * The catalogue key of a mnemonic as LLVM prints it in AArch32: the qualifiers
 * after the first dot go (`ldr.w`, `vadd.f32`), then a condition suffix if the
 * rest is not a mnemonic of its own (`bls` is b + ls, `bl` is bl, `vmovls` is
 * vmov + ls), and every IT block (`itte`) is `it`.
 */
export function arm32Key(mnemonic: string): string {
  const entries = ARM32().instructions;
  const base = mnemonic.split('.')[0]!;
  if (entries[base]) return base;
  if (/^it[te]{0,3}$/.test(base)) return 'it';
  const stripped = ARM32_CONDITIONS.has(base.slice(-2)) ? base.slice(0, -2) : base;
  if (entries[stripped]) return stripped;
  return ARM32_NAMES[stripped] ?? base;
}

/** Names LLVM prints that the catalogue files under another: the long coprocessor transfers, the default addressing mode, a trap. */
const ARM32_NAMES: Record<string, string> = { ldcl: 'ldc', stcl: 'stc', rfeia: 'rfe', srsia: 'srs', __brkdiv0: 'udf' };

/** The mnemonic without its condition, qualifiers kept: `addeq` → add, `vaddeq.f32` → vadd.f32, `bne` → b. */
export function arm32Unconditional(mnemonic: string): string {
  const dot = mnemonic.indexOf('.');
  const base = dot < 0 ? mnemonic : mnemonic.slice(0, dot);
  const key = arm32Key(base);
  return key === base || /^it/.test(base) ? mnemonic : key + (dot < 0 ? '' : mnemonic.slice(dot));
}

export const ARM64_CATALOGUE: Catalogue = {
  arch: 'arm64',
  lookup,
  lookupEnglish,
  key: catalogKey,
  mnemonics: allMnemonics,
  groups: ['base', 'fp', 'simd', 'system'],
  words: wordsFor('arm64', true),
  wordInstructions: (w) => w.instructions,
  wordExample: (w) => w.example,
  docUrl,
};

const wasmLookup = madeEntries(wasmEntry, { ru: parsed(wasmRuText) });

export const WASM_CATALOGUE: Catalogue = {
  arch: 'wasm',
  lookup: wasmLookup,
  lookupEnglish: wasmEntry,
  key: (name) => name,
  mnemonics: () => Object.keys(WASM_TEXTS().instructions),
  groups: ['control', 'parametric', 'variable', 'memory', 'numeric', 'vector', 'reference', 'table', 'aggregate', 'exception', 'atomic'],
  words: wordsFor('wasm', true),
  wordInstructions: (w) => w.wasm ?? [],
  wordExample: (w) => w.wasmExample ?? w.example,
  docUrl: (form) => form.url,
};

export const ARM32_CATALOGUE: Catalogue = {
  arch: 'arm32',
  lookup: (mnemonic) => ARM32_ENTRIES.lookup(arm32Key(mnemonic)),
  lookupEnglish: (mnemonic) => ARM32_ENTRIES.english(arm32Key(mnemonic)),
  key: arm32Key,
  mnemonics: () => Object.keys(ARM32().instructions),
  groups: ['base', 'fp', 'simd', 'system'],
  // HLA64 has no 32-bit Arm target: the view shows assembly only.
  words: () => [],
  wordInstructions: () => [],
  wordExample: (w) => w.example,
  docUrl: (form) => (form.url.startsWith('http') ? form.url : ARM32().docBase + form.url),
};

/* ------------------------------------------------------------------ *
 * x86
 * ------------------------------------------------------------------ */

const X86 = parsed<{ docBase: string; instructions: Record<string, Entry> }>(x86Text);
const X86_ENTRIES = entriesOf(X86, { ru: parsed(x86RuText) });
const X86_CC = 'o|no|b|ae|e|ne|be|a|s|ns|p|np|l|ge|le|g';
const X86_CONDITIONAL = new RegExp(`^(j|set|setzu|cmov|cfcmov|ccmp|ctest)(?:${X86_CC}|t|f)$`);
const X86_CMPXADD = new RegExp(`^cmp(?:${X86_CC})xadd$`);
const SSE_PREDICATES = 'eq|lt|le|unord|neq|nlt|nle|ord|eq_uq|nge|ngt|false|neq_oq|ge|gt|true|eq_os|lt_oq|le_oq|unord_s|neq_us|nlt_uq|nle_uq|ord_s|eq_us|nge_uq|ngt_uq|false_os|neq_os|ge_oq|gt_oq|true_us';
const X86_VCMP = new RegExp(`^(v?cmp)(?:${SSE_PREDICATES})(ps|pd|ss|sd|ph|sh|bf16)$`);
const X86_VPCMP = /^vpcmp(?:lt|le|neq|nlt|nle|eq(?=u))(u?[bwdq])$/;
const X86_VPCOM = /^vpcom(?:lt|le|gt|ge|eq|neq|false|true)(u?[bwdq])$/;

/**
 * The catalogue key of a mnemonic as LLVM prints it for x86: the condition
 * of jcc, setcc and cmovcc goes (`jne` is jcc), and so does the predicate the
 * printer folds into a vector compare (`cmpltps` is cmpps, `vpcmpgtd`… is
 * vpcmpd).
 */
export function x86Key(mnemonic: string): string {
  if (X86().instructions[mnemonic]) return mnemonic;
  const cc = X86_CONDITIONAL.exec(mnemonic);
  if (cc) return `${cc[1]}cc`;
  if (X86_CMPXADD.test(mnemonic)) return 'cmpccxadd';
  let m = X86_VCMP.exec(mnemonic);
  if (m) return `${m[1]}${m[2]}`;
  m = X86_VPCMP.exec(mnemonic);
  if (m) return `vpcmp${m[1]}`;
  m = X86_VPCOM.exec(mnemonic);
  if (m) return `vpcom${m[1]}`;
  return mnemonic;
}

/** The mnemonic with its condition or predicate folded away, for the statistics: `jne` → jcc. */
export const x86Unconditional = (mnemonic: string): string => x86Key(mnemonic);

export const X86_CATALOGUE: Catalogue = {
  arch: 'x86',
  lookup: (mnemonic) => X86_ENTRIES.lookup(x86Key(mnemonic)),
  lookupEnglish: (mnemonic) => X86_ENTRIES.english(x86Key(mnemonic)),
  key: x86Key,
  mnemonics: () => Object.keys(X86().instructions),
  groups: ['base', 'x87', 'simd', 'system'],
  words: wordsFor('x86', false),
  wordInstructions: (w) => w.x86 ?? [],
  wordExample: (w) => w.x86Example ?? w.example,
  docUrl: (form) => (!form.url || form.url.startsWith('http') ? form.url : X86().docBase + form.url),
};

/* ------------------------------------------------------------------ *
 * CIL
 * ------------------------------------------------------------------ */

interface CilText {
  summary: string;
  description: string;
  operation: string;
  /** The field of System.Reflection.Emit.OpCodes, whose page documents the instruction. */
  doc: string;
}

const CIL_TEXTS = parsed<{ docBase: string; instructions: Record<string, CilText> }>(cilText);
const CIL_OPS = new Map(cilOps().map((op) => [op.name, op]));
const ECMA_335 = 'https://ecma-international.org/publications-and-standards/standards/ecma-335/';

/** The operand of an instruction in ILAsm's syntax, as a template. */
const CIL_OPERANDS: Record<number, string> = {
  [OPERAND.NONE]: '', [OPERAND.VAR8]: ' index', [OPERAND.VAR16]: ' index', [OPERAND.I8]: ' int8', [OPERAND.U8]: ' uint8', [OPERAND.I32]: ' int32',
  [OPERAND.I64]: ' int64', [OPERAND.R4]: ' float32', [OPERAND.R8]: ' float64', [OPERAND.BR8]: ' target', [OPERAND.BR32]: ' target',
  [OPERAND.SWITCH]: ' (target, …)', [OPERAND.METHOD]: ' method', [OPERAND.FIELD]: ' field', [OPERAND.TYPE]: ' type', [OPERAND.STRING]: ' string',
  [OPERAND.SIG]: ' callsite', [OPERAND.TOKEN]: ' type | field | method',
};

/** How many values an instruction takes from the stack and leaves on it: `2 → 1`, `… → …` when its operand's signature says. */
function stackCounts(pop: number, push: number): string {
  const side = (n: number) => (n < 0 ? '…' : String(n));
  return `${side(pop)} → ${side(push)}`;
}

function cilEntry(name: string): Entry | undefined {
  const file = CIL_TEXTS();
  const text = file.instructions[name];
  const op = CIL_OPS.get(name);
  if (!text || !op) return undefined;
  return {
    summary: text.summary,
    description: text.description,
    operation: text.operation,
    flags: op.flags & CIL_F.TRAPS ? 'can throw' : 'none',
    category: op.category,
    group: op.group,
    stack: op.flags & CIL_F.PREFIX ? undefined : stackCounts(op.pop, op.push),
    forms: [{ heading: `${name} · ${cilOpcodeText(op.code)}`, syntax: [`${name}${CIL_OPERANDS[op.operand] ?? ''}`], url: text.doc ? file.docBase + text.doc.toLowerCase() : ECMA_335 }],
  };
}

export const CIL_CATALOGUE: Catalogue = {
  arch: 'cil',
  lookup: madeEntries(cilEntry, { ru: parsed(cilRuText) }),
  lookupEnglish: cilEntry,
  key: (name) => name,
  mnemonics: () => Object.keys(CIL_TEXTS().instructions),
  groups: ['il-base', 'il-object', 'il-prefix'],
  words: wordsFor('cil', false),
  wordInstructions: (w) => w.cil ?? [],
  wordExample: (w) => w.cilExample ?? w.example,
  docUrl: (form) => form.url,
};

/* ------------------------------------------------------------------ *
 * JVM
 * ------------------------------------------------------------------ */

interface JvmText {
  summary: string;
  description: string;
  operation: string;
  /** The anchor of the instruction's page in chapter 6 of the JVM specification (a family's: iload_n, if_cond). */
  doc: string;
}

const JVM_TEXTS = parsed<{ docBase: string; instructions: Record<string, JvmText> }>(jvmText);
const JVM_OPS = new Map(jvmOps().map((op) => [op.name, op]));

/** The operands of an instruction as javap writes them, as a template. */
const JVM_OPERANDS: Record<number, string> = {
  [JVM_OPERAND.NONE]: '', [JVM_OPERAND.LOCAL]: ' slot', [JVM_OPERAND.LOCAL_W]: ' slot', [JVM_OPERAND.IINC]: ' slot, const', [JVM_OPERAND.IINC_W]: ' slot, const',
  [JVM_OPERAND.BYTE]: ' byte', [JVM_OPERAND.SHORT]: ' short', [JVM_OPERAND.CP8]: ' #index', [JVM_OPERAND.CP16]: ' #index', [JVM_OPERAND.INTERFACE]: ' #index,  count',
  [JVM_OPERAND.DYNAMIC]: ' #index,  0', [JVM_OPERAND.DIMENSIONS]: ' #index,  dimensions', [JVM_OPERAND.ATYPE]: ' type', [JVM_OPERAND.BRANCH16]: ' target',
  [JVM_OPERAND.BRANCH32]: ' target', [JVM_OPERAND.TABLESWITCH]: ' { // low to high … default: target }', [JVM_OPERAND.LOOKUPSWITCH]: ' { // count key: target … default: target }',
  [JVM_OPERAND.JSR16]: '', [JVM_OPERAND.JSR32]: '', [JVM_OPERAND.RET]: '', [JVM_OPERAND.RET_W]: '',
};

/** What the stack operations do, in slots (a long or a double is two): their counts in values depend on what is on the stack. */
const JVM_STACK: Record<string, [number, number]> = { pop2: [2, 0], dup: [1, 2], dup_x1: [2, 3], dup_x2: [3, 4], dup2: [2, 4], dup2_x1: [3, 5], dup2_x2: [4, 6], swap: [2, 2] };

function jvmEntry(name: string): Entry | undefined {
  const file = JVM_TEXTS();
  const text = file.instructions[name];
  const op = JVM_OPS.get(name);
  if (!text || !op) return undefined;
  const slots = JVM_STACK[name];
  return {
    summary: text.summary,
    description: text.description,
    operation: text.operation,
    flags: op.flags & JVM_F.TRAPS ? 'can throw' : 'none',
    category: op.category,
    group: op.group,
    stack: slots ? t('stack', '{from} → {to} (slots)', { from: slots[0], to: slots[1] }) : stackCounts(op.pop, op.push),
    forms: [{ heading: `${name} · ${jvmOpcodeText(op.code)}`, syntax: [`${name}${JVM_OPERANDS[op.operand] ?? ''}`], url: file.docBase + text.doc }],
  };
}

export const JVM_CATALOGUE: Catalogue = {
  arch: 'jvm',
  lookup: madeEntries(jvmEntry, { ru: parsed(jvmRuText) }),
  lookupEnglish: jvmEntry,
  key: (name) => name,
  mnemonics: () => Object.keys(JVM_TEXTS().instructions),
  groups: ['jvm-constants', 'jvm-loads', 'jvm-stores', 'jvm-stack', 'jvm-math', 'jvm-conversions', 'jvm-comparisons', 'jvm-control', 'jvm-references', 'jvm-extended'],
  words: wordsFor('jvm', false),
  wordInstructions: (w) => w.jvm ?? [],
  wordExample: (w) => w.jvmExample ?? w.example,
  docUrl: (form) => form.url,
};

const CATALOGUES: Record<Arch, Catalogue> = { arm64: ARM64_CATALOGUE, arm32: ARM32_CATALOGUE, x86: X86_CATALOGUE, wasm: WASM_CATALOGUE, cil: CIL_CATALOGUE, jvm: JVM_CATALOGUE };

export function catalogueFor(arch: Arch): Catalogue {
  return CATALOGUES[arch];
}
