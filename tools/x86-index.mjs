/**
 * Builds the x86 decoding tables, src/core/x86/tables.ts, from LLVM's
 * description of the X86 target.
 *
 *   node tools/x86-index.mjs <llvm-project> [--tblgen path/to/llvm-tblgen]
 *
 * `<llvm-project>` is a checkout of LLVM (only llvm/include and
 * llvm/lib/Target/X86 are read; the version should match the llvm-objdump the
 * decoder is checked against). llvm-tblgen comes from LLVM_TBLGEN, --tblgen,
 * Homebrew's llvm@21 or the PATH.
 *
 * What is taken are facts about the encoding, not code: which instruction an
 * opcode byte, its prefixes and its ModR/M byte select in each context, where
 * each operand of it is encoded, and how LLVM's Intel printer writes it (the
 * Intel half of the instruction's assembly string, the print method of each
 * operand). The disassembler emitter of llvm-tblgen works the first out, the
 * JSON dump of the records gives the rest. The decoder in src/core/x86/ reads
 * them the way LLVM's X86 disassembler does, so the two print the same text.
 *
 * The tables are packed into one binary blob, compressed with deflate and kept
 * in base64; the decoder inflates it once (DecompressionStream) before use.
 * A summary of every mnemonic, its forms and its extension goes to
 * private/x86gen/mnemonics.json for the instruction catalogue.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { deflateRawSync } from 'node:zlib';
import { root } from './load.mjs';

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const at = args.indexOf(name);
  if (at < 0) return fallback;
  const [value] = args.splice(at, 2).slice(1);
  return value;
};
const tblgenOption = option('--tblgen', null);
const linksOption = option('--links', join(root, 'private', 'felix-pages.tsv'));
const llvm = args[0];
if (!llvm) {
  console.error('usage: node tools/x86-index.mjs <llvm-project> [--tblgen llvm-tblgen]');
  process.exit(2);
}
const src = existsSync(join(llvm, 'llvm', 'lib')) ? join(llvm, 'llvm') : llvm;

function tblgen() {
  for (const candidate of [tblgenOption, process.env.LLVM_TBLGEN, '/opt/homebrew/opt/llvm@21/bin/llvm-tblgen', '/usr/local/opt/llvm@21/bin/llvm-tblgen']) if (candidate && existsSync(candidate)) return candidate;
  return 'llvm-tblgen';
}

const out = join(root, 'private', 'x86gen');
mkdirSync(out, { recursive: true });
const td = ['-I', join(src, 'include'), '-I', join(src, 'lib', 'Target', 'X86'), join(src, 'lib', 'Target', 'X86', 'X86.td')];
const incPath = join(out, 'X86GenDisassemblerTables.inc');
const jsonPath = join(out, 'X86.json');
console.log('llvm-tblgen -gen-disassembler, -dump-json…');
execFileSync(tblgen(), ['-gen-disassembler', ...td, '-o', incPath], { stdio: 'inherit' });
execFileSync(tblgen(), ['-gen-asm-writer', '-asmwriternum=1', ...td, '-o', join(out, 'X86GenAsmWriter1.inc')], { stdio: 'inherit' });
execFileSync(tblgen(), ['-dump-json', ...td, '-o', jsonPath], { stdio: 'inherit' });
const llvmVersion = (() => {
  const cmake = join(src, 'CMakeLists.txt');
  const text = existsSync(cmake) ? readFileSync(cmake, 'utf8') : '';
  const part = (name) => new RegExp(`set\\(LLVM_VERSION_${name}\\s+(\\d+)`).exec(text)?.[1];
  const fromCmake = part('MAJOR') ? `${part('MAJOR')}.${part('MINOR')}.${part('PATCH')}` : '';
  if (fromCmake) return fromCmake;
  const versionFile = join(src, '..', 'cmake', 'Modules', 'LLVMVersion.cmake');
  const v = existsSync(versionFile) ? readFileSync(versionFile, 'utf8') : '';
  const p = (name) => new RegExp(`set\\(LLVM_VERSION_${name}\\s+(\\d+)`).exec(v)?.[1];
  return p('MAJOR') ? `${p('MAJOR')}.${p('MINOR')}.${p('PATCH')}` : 'unknown';
})();

/* ------------------------------------------------------------------ *
 * The enums the tables are written in (X86DisassemblerDecoderCommon.h)
 * ------------------------------------------------------------------ */

const common = readFileSync(join(src, 'include', 'llvm', 'Support', 'X86DisassemblerDecoderCommon.h'), 'utf8');
const enumList = (macro) => {
  const start = common.indexOf(`#define ${macro}`);
  const end = common.indexOf('\n\n', start);
  return [...common.slice(start, end).matchAll(/ENUM_ENTRY\((\w+)/g)].map((m) => m[1]);
};
const CONTEXTS = enumList('INSTRUCTION_CONTEXTS');
const ENCODINGS = enumList('ENCODINGS');
const TYPES = enumList('TYPES');
// The decoder (src/core/x86/decode.ts) switches on these numbers: they must not move.
const EXPECTED_ENCODINGS = ['ENCODING_NONE', 'ENCODING_REG', 'ENCODING_RM', 'ENCODING_RM_CD2', 'ENCODING_RM_CD4', 'ENCODING_RM_CD8', 'ENCODING_RM_CD16', 'ENCODING_RM_CD32', 'ENCODING_RM_CD64', 'ENCODING_SIB', 'ENCODING_VSIB', 'ENCODING_VSIB_CD2', 'ENCODING_VSIB_CD4', 'ENCODING_VSIB_CD8', 'ENCODING_VSIB_CD16', 'ENCODING_VSIB_CD32', 'ENCODING_VSIB_CD64', 'ENCODING_VVVV', 'ENCODING_WRITEMASK', 'ENCODING_IB', 'ENCODING_IW', 'ENCODING_ID', 'ENCODING_IO', 'ENCODING_RB', 'ENCODING_RW', 'ENCODING_RD', 'ENCODING_RO', 'ENCODING_FP', 'ENCODING_Iv', 'ENCODING_Ia', 'ENCODING_IRC', 'ENCODING_Rv', 'ENCODING_CC', 'ENCODING_CF', 'ENCODING_DUP', 'ENCODING_SI', 'ENCODING_DI'];
const EXPECTED_TYPES = ['TYPE_NONE', 'TYPE_REL', 'TYPE_R8', 'TYPE_R16', 'TYPE_R32', 'TYPE_R64', 'TYPE_IMM', 'TYPE_UIMM8', 'TYPE_M', 'TYPE_MSIB', 'TYPE_MVSIBX', 'TYPE_MVSIBY', 'TYPE_MVSIBZ', 'TYPE_SRCIDX', 'TYPE_DSTIDX', 'TYPE_MOFFS', 'TYPE_ST', 'TYPE_MM64', 'TYPE_XMM', 'TYPE_YMM', 'TYPE_ZMM', 'TYPE_VK', 'TYPE_VK_PAIR', 'TYPE_TMM', 'TYPE_TMM_PAIR', 'TYPE_SEGMENTREG', 'TYPE_DEBUGREG', 'TYPE_CONTROLREG', 'TYPE_BNDR', 'TYPE_Rv', 'TYPE_RELv', 'TYPE_DUP0', 'TYPE_DUP1', 'TYPE_DUP2', 'TYPE_DUP3', 'TYPE_DUP4'];
if (ENCODINGS.join() !== EXPECTED_ENCODINGS.join()) throw new Error(`operand encodings changed:\n${ENCODINGS.join(' ')}`);
if (TYPES.join() !== EXPECTED_TYPES.join()) throw new Error(`operand types changed:\n${TYPES.join(' ')}`);
const ATTR_MASKS = 1 << 16;

/* ------------------------------------------------------------------ *
 * X86GenDisassemblerTables.inc
 * ------------------------------------------------------------------ */

const inc = readFileSync(incPath, 'utf8');
const between = (start, end = '\n};') => {
  const a = inc.indexOf(start);
  if (a < 0) throw new Error(`not in the tables: ${start}`);
  return inc.slice(a + start.length, inc.indexOf(end, a));
};

const operandSets = [];
for (const m of between('x86OperandSets[][6] = {').matchAll(/\{ \/\* (\d+) \*\/((?:\s+\{ ENCODING_\w+, TYPE_\w+ \},){6})\s+\}/g)) {
  const ops = [...m[2].matchAll(/\{ (ENCODING_\w+), (TYPE_\w+) \}/g)].map((o) => [ENCODINGS.indexOf(o[1]), TYPES.indexOf(o[2])]);
  if (ops.some(([e, t]) => e < 0 || t < 0)) throw new Error(`unknown operand in set ${m[1]}`);
  operandSets[Number(m[1])] = ops;
}

const specs = [];
for (const m of between('x86DisassemblerInstrSpecifiers[').matchAll(/\{ \/\* (\d+) \*\/\s+(\d+),\s+\/\* (\S*) \*\/\s+\}/g)) specs[Number(m[1])] = { set: Number(m[2]), name: m[3] };

const contextOf = new Uint8Array(ATTR_MASKS);
for (const m of between('x86DisassemblerContexts[65536] = {').matchAll(/^\s+(IC\w*), \/\/ (\d+)$/gm)) {
  const ic = CONTEXTS.indexOf(m[1]);
  if (ic < 0) throw new Error(`unknown context ${m[1]}`);
  contextOf[Number(m[2])] = ic;
}

const modrm = [...between('modRMTable[] = {').matchAll(/0x([0-9a-f]+)/g)].map((m) => parseInt(m[1], 16));

const MAPS = ['OneByte', 'TwoByte', 'ThreeByte38', 'ThreeByte3A', 'XOP8', 'XOP9', 'XOPA', '3DNow', 'Map4', 'Map5', 'Map6', 'Map7'];
const MODRM_TYPES = ['MODRM_ONEENTRY', 'MODRM_SPLITRM', 'MODRM_SPLITMISC', 'MODRM_SPLITREG', 'MODRM_FULL'];
/** maps[map][context] = [type, offset][256] or null */
const maps = MAPS.map((name) => {
  const body = between(`x86Disassembler${name}Opcodes = {{`, '\n}};');
  const contexts = [];
  let current = null;
  for (const line of body.split('\n')) {
    let m = /^\s*\/\*(IC\w*)\*\/ \{\},/.exec(line);
    if (m) {
      contexts.push(null);
      continue;
    }
    m = /^\s*\/\*(IC\w*)\*\/ \{ \/\* struct OpcodeDecision \*\/ \{/.exec(line);
    if (m) {
      current = [];
      contexts.push(current);
      continue;
    }
    m = /\/\*0x([0-9a-f]{2})\*\/\{(MODRM_\w+), (\d+)\}/.exec(line);
    if (m) current.push([MODRM_TYPES.indexOf(m[2]), Number(m[3])]);
  }
  if (contexts.length !== CONTEXTS.length) throw new Error(`${name}: ${contexts.length} contexts, expected ${CONTEXTS.length}`);
  for (const c of contexts) if (c && c.length !== 256) throw new Error(`${name}: an opcode decision with ${c.length} entries`);
  return contexts;
});

/* ------------------------------------------------------------------ *
 * The instructions the tables can reach
 * ------------------------------------------------------------------ */

const used = new Set(modrm.filter((id) => id));
console.log(`${specs.length} instruction ids, ${used.size} reachable, ${operandSets.length} operand sets, ${modrm.length} ModR/M entries`);
console.log('reading the JSON dump…');
const records = JSON.parse(readFileSync(jsonPath, 'utf8'));

const def = (v) => (v && typeof v === 'object' && 'def' in v ? v.def : v);
const dagArgs = (dag) => (dag && typeof dag === 'object' && Array.isArray(dag.args) ? dag.args : []);
const bitsValue = (bits) => (Array.isArray(bits) ? bits.reduce((v, b, i) => v | ((b ? 1 : 0) << i), 0) : 0);

/** Flattens `{att|intel}` groups to the Intel variant, as TableGen does (CodeGenInstruction::FlattenAsmStringVariants). */
function intelVariant(s) {
  let res = '';
  for (;;) {
    let start = 0;
    while (start < s.length && !(s[start] === '{' && (start === 0 || (s[start - 1] !== '$' && s[start - 1] !== '\\')))) start++;
    res += s.slice(0, start);
    if (start === s.length) break;
    start++;
    let end = start;
    let nested = 1;
    for (; end < s.length; end++) {
      if (s[end] === '}' && s[end - 1] !== '\\') {
        if (--nested === 0) break;
      } else if (s[end] === '{') nested++;
    }
    const selection = s.slice(start, end);
    const bar = selection.indexOf('|');
    res += bar < 0 ? '' : selection.slice(bar + 1).split('|')[0];
    s = s.slice(end + 1);
  }
  return res;
}

const printMethods = ['printOperand'];
const methodId = (name) => {
  let id = printMethods.indexOf(name);
  if (id < 0) {
    id = printMethods.length;
    printMethods.push(name);
  }
  return id;
};

/** An instruction's operands as MCInst operands: name → { mi, count, method, cls }. */
function operandsOf(rec) {
  const list = [];
  let mi = 0;
  for (const dag of [rec.OutOperandList, rec.InOperandList]) {
    for (const [cls, name] of dagArgs(dag)) {
      const className = def(cls);
      const c = records[className];
      let count = 1;
      let method = 'printOperand';
      if (c) {
        const sub = dagArgs(c.MIOperandInfo);
        if (sub.length) count = sub.length;
        if (c.PrintMethod) method = c.PrintMethod;
      }
      list.push({ name, mi, count, method, cls: className });
      mi += count;
    }
  }
  return { list, total: mi };
}

const FORMS = Object.fromEntries(Object.entries(records).filter(([, r]) => r && Array.isArray(r['!superclasses']) && r['!superclasses'].includes('Format')).map(([n, r]) => [n, bitsValue(r.Value)]));

function compileTemplate(rec, name) {
  const asm = intelVariant(rec.AsmString ?? '');
  const { list } = operandsOf(rec);
  let t = '';
  for (let i = 0; i < asm.length; ) {
    const c = asm[i];
    if (c === '\\') {
      t += asm[i + 1] === 'n' ? '\n' : asm[i + 1] === 't' ? '\t' : asm[i + 1];
      i += 2;
    } else if (c === '$' && asm[i + 1] === '$') {
      t += '$';
      i += 2;
    } else if (c === '$') {
      let j = i + 1;
      const braces = asm[j] === '{';
      if (braces) j++;
      let k = j;
      while (k < asm.length && /\w/.test(asm[k])) k++;
      const opName = asm.slice(j, k);
      if (braces) {
        if (asm[k] === ':') throw new Error(`${name}: operand modifiers are not supported (${asm})`);
        if (asm[k] !== '}') throw new Error(`${name}: bad operand in ${asm}`);
        k++;
      }
      const op = list.find((o) => o.name === opName);
      if (!op) throw new Error(`${name}: no operand ${opName} in ${asm}`);
      if (op.mi > 60) throw new Error(`${name}: operand index too large`);
      t += `\x01${String.fromCharCode(65 + op.mi)}${String.fromCharCode(65 + methodId(op.method))}`;
      i = k;
    } else {
      t += c;
      i++;
    }
  }
  return t;
}

/** MCInstrDesc operand constraints: TIED_TO pairs as MI operand indices. */
function tiedOperands(rec) {
  const { list } = operandsOf(rec);
  const tied = new Map();
  for (const part of String(rec.Constraints ?? '').split(',')) {
    const m = /^\s*\$(\w+)\s*=\s*\$(\w+)\s*$/.exec(part);
    if (!m) continue;
    const a = list.find((o) => o.name === m[1]);
    const b = list.find((o) => o.name === m[2]);
    // Written either way round, the later operand is the one tied to the earlier.
    if (a && b) tied.set(Math.max(a.mi, b.mi), Math.min(a.mi, b.mi));
  }
  return tied;
}

/** X86II::getOperandBias. */
function operandBias(rec) {
  const { list, total } = operandsOf(rec);
  const defs = dagArgs(rec.OutOperandList).reduce((n, [cls]) => n + (list.find((o) => o.cls === def(cls))?.count ?? 1), 0);
  const tied = tiedOperands(rec);
  const tiedTo = (i) => (tied.has(i) ? tied.get(i) : -1);
  if (defs === 0) return 0;
  if (defs === 1) {
    if (total > 1 && tiedTo(1) === 0) return 1;
    if (total === 8 && tiedTo(6) === 0) return 1;
    return 0;
  }
  if (defs === 2) {
    if (total >= 4 && tiedTo(2) === 0 && tiedTo(3) === 1) return 2;
    if (total === 9 && tiedTo(2) === 0 && (tiedTo(3) === 1 || tiedTo(8) === 1)) return 2;
    return 0;
  }
  throw new Error(`${rec['!name']}: ${defs} defs`);
}

/** X86II::getMemoryOperandNo plus the bias, or -1. */
function memoryOperand(rec) {
  const form = def(rec.Form);
  const vvvv = !!rec.hasVEX_4V;
  const k = !!rec.hasEVEX_K;
  const ndd = def(rec.OpMap) === 'T_MAP4' && !!rec.hasEVEX_B && vvvv;
  let at;
  switch (form) {
    case 'MRMDestMem': case 'MRMDestMemFSIB': case 'MRMDestMemCC':
      at = ndd ? 1 : 0;
      break;
    case 'MRMSrcMem': case 'MRMSrcMemFSIB':
      at = 1 + vvvv + k;
      break;
    case 'MRMSrcMem4VOp3':
      at = 1 + k;
      break;
    case 'MRMSrcMemOp4':
      at = 3;
      break;
    case 'MRMSrcMemCC':
      at = 1 + ndd;
      break;
    case 'MRMDestMem4VOp3CC':
      at = 1;
      break;
    default:
      if (/^MRM[0-7X]m$|^MRMXmCC$/.test(form)) {
        at = 0 + vvvv + k;
        break;
      }
      return -1;
  }
  return at + operandBias(rec);
}

// What the decoder needs of each reachable instruction, in a dense numbering (0 = none).
const ids = [0, ...[...used].sort((a, b) => a - b)];
const denseOf = new Map(ids.map((id, i) => [id, i]));
const templates = [''];
const templateOf = new Map([['', 0]]);
const n = ids.length;
const opset = new Uint16Array(n);
const template = new Uint16Array(n);
const info = new Uint32Array(n);
const sem = new Uint32Array(n);
const names = [''];

// Bits of `info`, read by src/core/x86/decode.ts.
const I = {
  MEMOP_SHIFT: 0, // 4 bits: the memory operand's MI index, 15 = none
  ADSIZE_SHIFT: 4, // 2 bits: 0 any, 1 AdSize16, 2 AdSize32, 3 AdSize64
  RAW_SHIFT: 6, // 2 bits: 0, 1 RawFrmDstSrc, 2 RawFrmSrc, 3 RawFrmDst
  LOCK: 1 << 8,
  NOTRACK: 1 << 9,
  NF: 1 << 10, // prints {nf} (EVEX_NF, not CFCMOV)
  EXPLICIT_VEX: 1 << 11,
  EXPLICIT_EVEX: 1 << 12,
  NAME64: 1 << 13, // the LLVM name has "64" in it
  VCMP_SHIFT: 14, // 3 bits: 0, 1 cmp (SSE), 2 vcmp, 3 vpcom, 4 vpcmp
  SRCMEM: 1 << 17, // Form == MRMSrcMem
  XS: 1 << 18,
  XD: 1 << 19,
  TA: 1 << 20, // OpMap == TA
  EVEX_K: 1 << 21,
  EVEX_B: 1 << 22,
  REX_W: 1 << 23,
  EVEX_L2: 1 << 24,
  VEX_L: 1 << 25,
  SUFFIX_SHIFT: 26, // 4 bits: the vector compare's suffix
  CCMP: 1 << 30, // ccmp/ctest: condition codes 10 and 11 print as t and f
};
const SUFFIXES = ['', 'pd', 'ps', 'sd', 'ss', 'ph', 'sh', 'bf16', 'b', 'w', 'd', 'q', 'ub', 'uw', 'ud', 'uq'];
// Bits of `sem`, for the analysis.
const S = { CALL: 1, BRANCH: 2, RET: 4, INDIRECT: 8, COND: 16, BARRIER: 32, TRAP: 64, LOAD: 128, STORE: 256, SETS_FLAGS: 512, READS_FLAGS: 1024, PREFIX: 2048 };

// The vector compares LLVM's Intel printer writes with the predicate in the mnemonic (X86IntelInstPrinter::printVecCompareInstr).
const printerSource = readFileSync(join(src, 'lib', 'Target', 'X86', 'MCTargetDesc', 'X86IntelInstPrinter.cpp'), 'utf8');
const vecCompare = new Map();
{
  const body = printerSource.slice(printerSource.indexOf('bool X86IntelInstPrinter::printVecCompareInstr'), printerSource.indexOf('void X86IntelInstPrinter::printOperand'));
  // Each block is its case labels, then the immediate's range, then the mnemonic printer that says which kind it is.
  const RANGES = { 1: 'Imm >= 0 && Imm <= 7', 2: 'Imm >= 0 && Imm <= 31', 3: 'Imm >= 0 && Imm <= 7', 4: '(Imm >= 0 && Imm <= 2) || (Imm >= 4 && Imm <= 6)' };
  let pending = [];
  let range = '';
  for (const m of body.matchAll(/case X86::(\w+):|if \(((?:\(?Imm >= 0 && Imm <= \d+\)?)(?: \|\| \(Imm >= 4 && Imm <= 6\))?)\) \{|printCMPMnemonic\(MI, \/\*IsVCMP\*\/(false|true)|printVPCOMMnemonic\(MI|printVPCMPMnemonic\(MI/g)) {
    if (m[1]) pending.push(m[1]);
    else if (m[2]) range = m[2];
    else {
      const kind = m[3] === 'false' ? 1 : m[3] === 'true' ? 2 : m[0].startsWith('printVPCOM') ? 3 : 4;
      if (range !== RANGES[kind]) throw new Error(`printVecCompareInstr: unexpected range ${range} for kind ${kind}`);
      for (const name of pending) vecCompare.set(name, { kind });
      pending = [];
    }
  }
  if (vecCompare.size < 260) throw new Error(`printVecCompareInstr: only ${vecCompare.size} instructions found`);
}
const suffixOf = (name, kind) => {
  if (kind === 1 || kind === 2) return SUFFIXES.indexOf(/^V?CMP(PD|PS|SD|SS|PH|SH|BF16)/.exec(name)[1].toLowerCase());
  return SUFFIXES.indexOf(/^VP(?:COM|CMP)(U?[BWDQ])/.exec(name)[1].toLowerCase());
};

const isCFCMOV = (name) => /^CFCMOV/.test(name);
for (let d = 1; d < n; d++) {
  const id = ids[d];
  const spec = specs[id];
  const name = spec.name;
  names.push(name);
  const rec = records[name];
  if (!rec) throw new Error(`no record for ${name}`);
  opset[d] = spec.set;
  const t = compileTemplate(rec, name);
  let ti = templateOf.get(t);
  if (ti === undefined) {
    ti = templates.length;
    templates.push(t);
    templateOf.set(t, ti);
  }
  template[d] = ti;
  const mem = memoryOperand(rec);
  const adsize = { AdSize16: 1, AdSize32: 2, AdSize64: 3 }[def(rec.AdSize)] ?? 0;
  const raw = { RawFrmDstSrc: 1, RawFrmSrc: 2, RawFrmDst: 3 }[def(rec.Form)] ?? 0;
  const explicit = def(rec.explicitOpPrefix);
  const vc = vecCompare.get(name);
  let bits = ((mem < 0 ? 15 : mem) << I.MEMOP_SHIFT) | (adsize << I.ADSIZE_SHIFT) | (raw << I.RAW_SHIFT);
  if (mem > 14) throw new Error(`${name}: memory operand ${mem}`);
  if (rec.hasLockPrefix) bits |= I.LOCK;
  if (rec.hasNoTrackPrefix) bits |= I.NOTRACK;
  if (rec.hasEVEX_NF && !isCFCMOV(name)) bits |= I.NF;
  if (explicit === 'ExplicitVEX') bits |= I.EXPLICIT_VEX;
  if (explicit === 'ExplicitEVEX') bits |= I.EXPLICIT_EVEX;
  if (/64/.test(name)) bits |= I.NAME64;
  if (vc) bits |= (vc.kind << I.VCMP_SHIFT) | (suffixOf(name, vc.kind) << I.SUFFIX_SHIFT);
  if (def(rec.Form) === 'MRMSrcMem') bits |= I.SRCMEM;
  if (def(rec.OpPrefix) === 'XS') bits |= I.XS;
  if (def(rec.OpPrefix) === 'XD') bits |= I.XD;
  if (def(rec.OpMap) === 'TA') bits |= I.TA;
  if (rec.hasEVEX_K) bits |= I.EVEX_K;
  if (rec.hasEVEX_B) bits |= I.EVEX_B;
  if (rec.hasREX_W) bits |= I.REX_W;
  if (rec.hasEVEX_L2) bits |= I.EVEX_L2;
  if (rec.hasVEX_L) bits |= I.VEX_L;
  if (/^(CCMP|CTEST)/.test(name)) bits |= I.CCMP;
  info[d] = bits >>> 0;

  // What the analysis wants to know.
  let s = 0;
  const defs = (rec.Defs ?? []).map(def);
  const uses = (rec.Uses ?? []).map(def);
  if (rec.isCall) s |= S.CALL;
  if (rec.isBranch || rec.isIndirectBranch) s |= S.BRANCH;
  if (rec.isReturn) s |= S.RET | S.BRANCH;
  if (rec.isIndirectBranch || (rec.isCall && !/pcrel/i.test(name))) s |= S.INDIRECT;
  if ((rec.isBranch && !rec.isBarrier && !rec.isIndirectBranch) || /^J[A-Z]*CXZ|^LOOP/.test(name)) s |= S.COND;
  if (rec.isBarrier) s |= S.BARRIER;
  if (rec.isTrap || /^(UD[012]|INT3|HLT|TRAP)/.test(name)) s |= S.TRAP;
  const form = def(rec.Form);
  const hasMem = operandsOf(rec).list.some((o) => records[o.cls]?.OperandType === 'OPERAND_MEMORY' && !/^(lea|anymem)/.test(o.cls) && !/^LEA/.test(name));
  if (hasMem) {
    if (rec.mayLoad === 1 || (rec.mayLoad == null && (form.startsWith('MRMSrcMem') || /^MRM[0-7X]m/.test(form) || form === 'RawFrmMemOffs' || form.startsWith('RawFrmSrc') || form === 'RawFrmDstSrc'))) s |= S.LOAD;
    if (rec.mayStore === 1 || (rec.mayStore == null && (form.startsWith('MRMDestMem') || form === 'RawFrmDst' || form === 'RawFrmDstSrc'))) s |= S.STORE;
  }
  if (defs.includes('EFLAGS')) s |= S.SETS_FLAGS;
  if (uses.includes('EFLAGS')) s |= S.READS_FLAGS;
  if (form === 'PrefixByte') s |= S.PREFIX;
  sem[d] = s;
}

// 16-bit equivalents (getInstructionID): for each context pair that OPSIZE turns one into the other, the ids it pairs.
const is16BitEquivalent = (orig, equiv) => {
  if (orig.length !== equiv.length) return false;
  for (let i = 0; i < orig.length; i++) {
    const a = orig[i];
    const b = equiv[i];
    if (a === b) continue;
    if ((a === 'Q' || a === 'L') && b === 'W') continue;
    if ((a === '6' || a === '3') && b === '1') continue;
    if ((a === '4' || a === '2') && b === '6') continue;
    return false;
  }
  return true;
};
const decodeId = (map, ctx, opcode, modRM) => {
  const block = maps[map][ctx];
  if (!block) return 0;
  const [type, off] = block[opcode];
  const mod3 = modRM >> 6 === 3;
  switch (type) {
    case 0: return modrm[off];
    case 1: return modrm[off + (mod3 ? 1 : 0)];
    case 2: return modrm[off + (mod3 ? (modRM & 0x3f) + 8 : (modRM & 0x38) >> 3)];
    case 3: return modrm[off + (mod3 ? ((modRM & 0x38) >> 3) + 8 : (modRM & 0x38) >> 3)];
    default: return modrm[off + modRM];
  }
};
const ATTR_OPSIZE = 0x10;
const pairs = new Set();
const contextPairs = new Set();
for (let mask = 0; mask < ATTR_MASKS; mask++) if (!(mask & ATTR_OPSIZE)) contextPairs.add(contextOf[mask] * 1024 + contextOf[mask | ATTR_OPSIZE]);
for (const key of contextPairs) {
  const a = Math.floor(key / 1024);
  const b = key % 1024;
  if (a === b) continue;
  for (let map = 0; map < MAPS.length; map++) {
    if (!maps[map][a] || !maps[map][b]) continue;
    for (let opcode = 0; opcode < 256; opcode++) {
      for (let m = 0; m < 256; m++) {
        const x = decodeId(map, a, opcode, m);
        const y = decodeId(map, b, opcode, m);
        if (x && y && x !== y && is16BitEquivalent(specs[x].name, specs[y].name)) pairs.add(denseOf.get(x) * 65536 + denseOf.get(y));
      }
    }
  }
}

/* ------------------------------------------------------------------ *
 * The aliases the printer prefers (printAliasInstr)
 * ------------------------------------------------------------------ */

const writer = readFileSync(join(out, 'X86GenAsmWriter1.inc'), 'utf8');
const aliasBody = writer.slice(writer.indexOf('bool X86IntelInstPrinter::printAliasInstr'), writer.indexOf('void X86IntelInstPrinter::printCustomAliasOperand'));
const toPatterns = [...aliasBody.slice(aliasBody.indexOf('OpToPatterns[]'), aliasBody.indexOf('Patterns[] = {', aliasBody.indexOf('OpToPatterns[]') + 20)).matchAll(/\{X86::(\w+), (\d+), (\d+) \}/g)];
const patternList = [...aliasBody.slice(aliasBody.indexOf('AliasPattern Patterns[]'), aliasBody.indexOf('AliasPatternCond Conds[]')).matchAll(/\{(\d+), (\d+), (\d+), (\d+) \}/g)].map((m) => m.slice(1).map(Number));
const condList = [...aliasBody.slice(aliasBody.indexOf('AliasPatternCond Conds[]'), aliasBody.indexOf('AsmStrings[]')).matchAll(/\{AliasPatternCond::(K_\w+), (?:uint32_t\()?(\d+)\)?\}/g)].map((m) => [m[1], Number(m[2])]);
const asmStrings = aliasBody.slice(aliasBody.indexOf('AsmStrings[] ='), aliasBody.indexOf(';', aliasBody.indexOf('AsmStrings[] ='))).replace(/\/\* \d+ \*\//g, '');
const stringAt = new Map();
{
  let at = 0;
  for (const m of asmStrings.matchAll(/"((?:[^"\\]|\\.)*)"/g)) {
    const text = m[1].replace(/\\0$/, '').replace(/\\t/g, '\t');
    if (/\\/.test(text)) throw new Error(`alias string with escapes: ${text}`);
    stringAt.set(at, text);
    at += text.length + 1;
  }
}
const aliases = [];
for (const m of toPatterns) {
  const dense = denseOf.get(specs.findIndex((s) => s?.name === m[1]));
  if (!dense) continue;
  for (let p = Number(m[2]); p < Number(m[2]) + Number(m[3]); p++) {
    const [strAt, condAt, , numConds] = patternList[p];
    const conds = condList.slice(condAt, condAt + numConds);
    if (conds.some(([kind]) => kind !== 'K_Imm' && kind !== 'K_Ignore')) throw new Error(`alias of ${m[1]}: conditions this tool does not read`);
    const text = stringAt.get(strAt);
    if (text === undefined || text.includes('$')) throw new Error(`alias of ${m[1]}: operands in ${text}`);
    aliases.push([dense, conds.map(([kind, v], i) => (kind === 'K_Imm' ? [i, v] : null)).filter(Boolean), text]);
  }
}

/* ------------------------------------------------------------------ *
 * Registers: names of the classes the decoder produces
 * ------------------------------------------------------------------ */

const asmName = (reg) => records[reg]?.AsmName;
for (const reg of ['RAX', 'SPL', 'R31B', 'ST1', 'K7', 'TMM7', 'DR15', 'CR15', 'RIZ', 'EIZ', 'RIP', 'XMM31', 'ZMM31', 'MM7']) if (!asmName(reg)) throw new Error(`no register ${reg}`);
const regCheck = { ST0: asmName('ST0'), ST1: asmName('ST1'), R16: asmName('R16'), R31B: asmName('R31B'), R8B: asmName('R8B'), R8W: asmName('R8W'), R8D: asmName('R8D') };
if (JSON.stringify(regCheck) !== JSON.stringify({ ST0: 'st', ST1: 'st(1)', R16: 'r16', R31B: 'r31b', R8B: 'r8b', R8W: 'r8w', R8D: 'r8d' })) throw new Error(`register names changed: ${JSON.stringify(regCheck)}`);

/* ------------------------------------------------------------------ *
 * Packing
 * ------------------------------------------------------------------ */

const blocks = [];
const blockOf = new Map();
const ctxBlock = new Uint16Array(MAPS.length * CONTEXTS.length);
for (let map = 0; map < MAPS.length; map++) {
  for (let ctx = 0; ctx < CONTEXTS.length; ctx++) {
    const block = maps[map][ctx];
    if (!block) continue;
    const key = block.map(([t, o]) => `${t}:${o}`).join(',');
    let b = blockOf.get(key);
    if (b === undefined) {
      b = blocks.length;
      blocks.push(block);
      blockOf.set(key, b);
    }
    ctxBlock[map * CONTEXTS.length + ctx] = b + 1;
  }
}
const blockTypes = new Uint8Array(blocks.length * 256);
const blockOffsets = new Uint16Array(blocks.length * 256);
blocks.forEach((block, b) => block.forEach(([t, o], i) => {
  if (o > 0xffff) throw new Error('ModR/M offset too large');
  blockTypes[b * 256 + i] = t;
  blockOffsets[b * 256 + i] = o;
}));
const modrmDense = Uint16Array.from(modrm, (id) => denseOf.get(id) ?? 0);
const sets = new Uint8Array(operandSets.length * 12);
operandSets.forEach((ops, i) => ops.forEach(([e, t], k) => {
  sets[i * 12 + k * 2] = e;
  sets[i * 12 + k * 2 + 1] = t;
}));
const pairList = Uint32Array.from([...pairs].sort((a, b) => a - b));
const templateBytes = Buffer.from(templates.join('\0'), 'latin1');

const parts = [
  ['contexts', contextOf],
  ['ctxBlock', ctxBlock],
  ['blockTypes', blockTypes],
  ['blockOffsets', blockOffsets],
  ['modrm', modrmDense],
  ['opset', opset],
  ['template', template],
  ['info', info],
  ['sem', sem],
  ['sets', sets],
  ['pairs', pairList],
  ['templates', new Uint8Array(templateBytes)],
];
// Each part: its byte length (u32), then its bytes, padded to 4.
let size = 0;
for (const [, a] of parts) size += 4 + ((a.byteLength + 3) & ~3);
const blob = Buffer.alloc(size);
let at = 0;
for (const [, a] of parts) {
  blob.writeUInt32LE(a.byteLength, at);
  Buffer.from(a.buffer, a.byteOffset, a.byteLength).copy(blob, at + 4);
  at += 4 + ((a.byteLength + 3) & ~3);
}
const packed = deflateRawSync(blob, { level: 9 });
console.log(`${blocks.length} opcode tables, ${templates.length} templates, ${pairs.size} 16-bit pairs, ${aliases.length} aliases; ${blob.length.toLocaleString()} bytes, ${packed.length.toLocaleString()} deflated`);

const ts = `/**
 * The x86 decoding tables, generated by tools/x86-index.mjs from the X86
 * target description of LLVM ${llvmVersion} (llvm-tblgen -gen-disassembler and
 * -dump-json). Do not edit: run the tool again.
 *
 * LLVM is under the Apache License 2.0 with LLVM Exceptions. What is kept here
 * are facts about the encoding: which instruction each opcode selects in each
 * context, where its operands are encoded, and the Intel syntax of each.
 */

export const LLVM_VERSION = '${llvmVersion}';
export const CONTEXT_COUNT = ${CONTEXTS.length};
export const PRINT_METHODS = ${JSON.stringify(printMethods)} as const;
export const SUFFIXES = ${JSON.stringify(SUFFIXES)} as const;
/** [instruction, [[operand, value]…], text]: printed as the text when its immediates have those values. */
export const ALIASES: [number, [number, number][], string][] = ${JSON.stringify(aliases)};
/** The parts of the blob, in order. */
export const PARTS = ${JSON.stringify(parts.map(([name]) => name))} as const;
/** What rep and repne print as before a locked instruction or an xchg (they are not in the tables). */
export const XRELEASE = ${JSON.stringify(intelVariant(records.XRELEASE_PREFIX.AsmString))};
export const XACQUIRE = ${JSON.stringify(intelVariant(records.XACQUIRE_PREFIX.AsmString))};
/** Instructions the decoder treats specially, by LLVM's name. */
export const SPECIAL = ${JSON.stringify(Object.fromEntries(['REP_PREFIX', 'REPNE_PREFIX', 'LOCK_PREFIX', 'DATA16_PREFIX'].map((name) => [name, denseOf.get(specs.findIndex((s) => s?.name === name)) ?? 0])))} as const;
export const BLOB = '${packed.toString('base64')}';
`;
writeFileSync(join(root, 'src', 'core', 'x86', 'tables.ts'), ts);

/* ------------------------------------------------------------------ *
 * The instruction catalogue: src/data/x86-instructions.json
 * ------------------------------------------------------------------ */

// Each key: the mnemonic as printed, with the condition of jcc/setcc/cmovcc as `cc` (src/core/catalog.ts x86Key).
const keyOfTemplate = (t) => {
  const m = /^([^\t\x01]*)(?:\x01..)?/.exec(t);
  const head = t.split('\t')[0];
  if (/\x01.K/.test(head) || head.includes(String.fromCharCode(65 + printMethods.indexOf('printCondCode')))) {
    // A condition in the mnemonic: `j${cond}` is jcc.
    return head.replace(/\x01../g, 'cc');
  }
  return m[1].split('\t')[0];
};

const OPERAND_KINDS = [
  [/^GR8/, 'r8'], [/^GR16/, 'r16'], [/^GR32/, 'r32'], [/^GR64/, 'r64'], [/^VR64$/, 'mm'], [/^(VR128|FR16|FR32|FR64|FR128)/, 'xmm'],
  [/^VR256/, 'ymm'], [/^VR512/, 'zmm'], [/^VK\d*Pair|^VK.*PAIR/, 'k'], [/^VK/, 'k'], [/^RST/, 'st(i)'], [/^SEGMENT_REG$/, 'sreg'],
  [/^CONTROL_REG$/, 'cr'], [/^DEBUG_REG$/, 'dr'], [/^TILE/, 'tmm'], [/^BNDR/, 'bnd'],
];
const MEM_KINDS = { printbytemem: 'm8', printwordmem: 'm16', printdwordmem: 'm32', printqwordmem: 'm64', printxmmwordmem: 'm128', printymmwordmem: 'm256', printzmmwordmem: 'm512', printtbytemem: 'm80', printMemReference: 'm' };
function operandKind(op) {
  const c = records[op.cls];
  const pm = op.method;
  if (/^v[xyz]\d+[xyz]?mem$/.test(op.cls)) return `vm${op.cls.match(/\d+/)[0]}${op.cls[1]}`;
  if (MEM_KINDS[pm]) return MEM_KINDS[pm];
  let m = /^printMemOffs(\d+)$/.exec(pm);
  if (m) return `moffs${m[1]}`;
  m = /^print(?:Src|Dst)Idx(\d+)$/.exec(pm);
  if (m) return `m${m[1]}`;
  if (pm === 'printPCRelImm') return /8$/.test(op.cls) ? 'rel8' : /16/.test(op.cls) ? 'rel16' : 'rel32';
  if (pm === 'printU8Imm') return 'imm8';
  if (pm === 'printCondCode') return 'cc';
  if (pm === 'printRoundingControl') return '{er}';
  if (pm === 'printCondFlags') return '{dfv=}';
  if (pm === 'printSTiRegOperand') return 'st(i)';
  if (pm === 'printVKPair') return 'k';
  if (pm === 'printTILEPair') return 'tmm';
  const superclasses = c?.['!superclasses'] ?? [];
  const reg = superclasses.includes('RegisterClass') ? op.cls : superclasses.includes('RegisterOperand') ? def(c.RegClass) : null;
  if (reg) for (const [re, kind] of OPERAND_KINDS) if (re.test(reg)) return kind;
  m = /^i\d+i(\d+)imm/.exec(op.cls) ?? /^[iu](\d+)imm/.exec(op.cls) ?? /^i(\d+)u8imm/.exec(op.cls);
  if (m) return `imm${op.cls.includes('u8imm') ? 8 : m[1]}`;
  if (/brtarget/.test(op.cls)) return 'rel32';
  return reg ? reg.toLowerCase() : op.cls;
}

/** The Intel syntax of a form with operand kinds: `add r/m64`… as `add r64, r64`. */
function formSyntax(rec, name) {
  const asm = intelVariant(rec.AsmString ?? '');
  const { list } = operandsOf(rec);
  return asm
    .replace(/\$\{?(\w+)\}?/g, (_, n) => {
      const op = list.find((o) => o.name === n);
      return op ? operandKind(op) : n;
    })
    .replace(/\t+/g, ' ')
    .replace(/ccq?\b(?=\s|$)/, 'cc')
    .trim();
}

const hex2 = (v) => v.toString(16).toUpperCase().padStart(2, '0');
const MAP_BYTES = { OB: '', TB: '0F', T8: '0F 38', TA: '0F 3A', ThreeDNow: '0F 0F' };
const VEX_MAPS = { TB: '0F', T8: '0F38', TA: '0F3A', T_MAP4: 'MAP4', T_MAP5: 'MAP5', T_MAP6: 'MAP6', T_MAP7: 'MAP7', XOP8: 'M08', XOP9: 'M09', XOPA: 'M0A' };
const PREFIX_BYTES = { PD: '66', XS: 'F3', XD: 'F2' };
const IMM_SUFFIX = { Imm8: 'ib', Imm8Reg: 'is4', Imm16: 'iw', Imm32: 'id', Imm32S: 'id', Imm64: 'io', Imm8PCRel: 'cb', Imm16PCRel: 'cw', Imm32PCRel: 'cd' };

/** The encoding as the manuals write it: `REX.W 01 /r`, `EVEX.512.66.0F.W0 FE /r`. */
function formEncoding(rec) {
  const form = def(rec.Form);
  const map = def(rec.OpMap);
  const prefix = def(rec.OpPrefix);
  const enc = def(rec.OpEnc);
  const opcode = bitsValue(rec.Opcode);
  let reg = '';
  let m;
  if ((m = /^MRM([0-7])[rmX]/.exec(form))) reg = `/${m[1]}`;
  else if (/^MRM(Dest|Src|X)/.test(form)) reg = '/r';
  else if ((m = /^MRM_([0-9A-F]{2})$/.exec(form))) reg = m[1];
  const plus = form === 'AddRegFrm' ? '+r' : form === 'AddCCFrm' || /CC$/.test(form) ? '+cc' : '';
  const imm = IMM_SUFFIX[def(rec.ImmT)] ?? '';
  if (enc === 'EncNormal') {
    const parts = [];
    if (def(rec.OpSize) === 'OpSize16') parts.push('66');
    if (PREFIX_BYTES[prefix]) parts.push(PREFIX_BYTES[prefix]);
    if (rec.hasREX_W) parts.push('REX.W');
    if (MAP_BYTES[map]) parts.push(MAP_BYTES[map]);
    if (map === 'T_MAP4') parts.push('EVEX.MAP4');
    parts.push(`${hex2(opcode)}${plus}`);
    if (reg) parts.push(reg);
    if (imm) parts.push(imm);
    return parts.join(' ');
  }
  const kind = enc === 'EncVEX' ? 'VEX' : enc === 'EncEVEX' ? 'EVEX' : 'XOP';
  const length = rec.ignoresVEX_L ? 'LIG' : rec.hasEVEX_L2 ? '512' : rec.hasVEX_L ? '256' : kind === 'EVEX' && !rec.hasEVEX_L2 && !rec.hasVEX_L ? '128' : rec.hasVEX_L ? '256' : '128';
  const w = rec.IgnoresW ? 'WIG' : rec.hasREX_W ? 'W1' : 'W0';
  const head = [kind, length, PREFIX_BYTES[prefix], VEX_MAPS[map], w].filter(Boolean).join('.');
  return [head, `${hex2(opcode)}${plus}`, reg, imm].filter(Boolean).join(' ');
}

const EXTENSION_NAMES = { AVX512: 'AVX512F', BWI: 'AVX512BW', DQI: 'AVX512DQ', VLX: 'AVX512VL', CDI: 'AVX512CD', VBMI: 'AVX512_VBMI', VBMI2: 'AVX512_VBMI2', IFMA: 'AVX512_IFMA', VNNI: 'AVX512_VNNI', BITALG: 'AVX512_BITALG', VPOPCNTDQ: 'AVX512_VPOPCNTDQ', FP16: 'AVX512_FP16', BF16: 'AVX512_BF16', VP2INTERSECT: 'AVX512_VP2INTERSECT', X87: 'x87', MMX: 'MMX', SSE1: 'SSE', SSEPrefetch: 'SSE', FMA: 'FMA', AVX1Only: 'AVX', EGPR: 'APX', NDD: 'APX', CF: 'APX', CMOV: 'CMOV', CX8: 'CMPXCHG8B', CX16: 'CMPXCHG16B' };
/** The extensions a form needs, from its predicates: SSE2, AVX512F, BMI2; `x86-64` or `i386` when only one mode has it. */
function extensionsOf(rec) {
  const out = [];
  for (const p of (rec.Predicates ?? []).map(def)) {
    if (p === 'In64BitMode' || p === 'IsLP64') out.push('x86-64');
    else if (p === 'Not64BitMode' || p === 'In32BitMode') out.push('i386');
    else {
      const m = /^(?:Has|Use)(\w+)$/.exec(p);
      if (!m || /^(Fast|Slow|Favor|Import|Indirect)/.test(m[1])) continue;
      out.push(EXTENSION_NAMES[m[1]] ?? m[1].replace(/_/g, '.'));
    }
  }
  return [...new Set(out)];
}

/** The page of the HTML edition of Intel's manual that describes a mnemonic, if there is one. */
const pages = new Map();
if (linksOption && existsSync(linksOption)) {
  for (const line of readFileSync(linksOption, 'utf8').split('\n')) {
    const [page, name] = line.split('\t');
    if (page && name && !pages.has(name.toLowerCase())) pages.set(name.toLowerCase(), page);
  }
}
const pageOf = (key) => pages.get(key) ?? (key.startsWith('v') ? pages.get(key.slice(1)) : undefined) ?? (/cc$/.test(key) ? pages.get(key) : undefined);

const catalogPath = join(root, 'src', 'data', 'x86-instructions.json');
const previous = existsSync(catalogPath) ? JSON.parse(readFileSync(catalogPath, 'utf8')) : { instructions: {} };
const entries = new Map();
for (let d = 1; d < n; d++) {
  const name = names[d];
  const rec = records[name];
  if (rec.isCodeGenOnly && !rec.ForceDisassemble) {
    // Still reachable through the tables (the decoder found it), so it is listed.
  }
  const key = keyOfTemplate(templates[template[d]]);
  if (!key || key.includes('\x01')) continue;
  const entry = entries.get(key) ?? { forms: new Map(), defs: false, uses: false, records: [] };
  const syntax = formSyntax(rec, name);
  const encoding = formEncoding(rec);
  // Forms with one encoding are one form; their variants (a mask, a broadcast, memory or register) are its syntax lines.
  const isa = extensionsOf(rec);
  const formKey = `${encoding}|${isa.join(',')}`;
  const form = entry.forms.get(formKey);
  if (!form) entry.forms.set(formKey, { heading: encoding, syntax: [syntax], isa });
  else if (!form.syntax.includes(syntax)) form.syntax.push(syntax);
  if ((rec.Defs ?? []).map(def).includes('EFLAGS')) entry.defs = true;
  if ((rec.Uses ?? []).map(def).includes('EFLAGS')) entry.uses = true;
  entry.records.push(rec);
  entries.set(key, entry);
}
const groupOf = (entry) => {
  const r = entry.records[0];
  const supers = r['!superclasses'] ?? [];
  if (supers.some((c) => /^FP(I|ST0|rST0|_|I_)|^FPI$/.test(c)) || /^HasX87$/.test((r.Predicates ?? []).map(def).join(','))) return 'x87';
  const vector = entry.records.some((rec) => operandsOf(rec).list.some((o) => /^(xmm|ymm|zmm|mm|k|m128|m256|m512|tmm)$/.test(operandKind(o)) || /^vm/.test(operandKind(o))));
  return vector ? 'simd' : 'base';
};
const instructions = {};
for (const [key, entry] of [...entries].sort((a, b) => a[0].localeCompare(b[0]))) {
  const old = previous.instructions[key] ?? {};
  const page = pageOf(key);
  // Legacy and VEX first, then EVEX, the APX promotions last; a long list is cut.
  // Within each, the 16-bit forms (66) and the ones only i386 has come after the rest.
  const rank = (f) => (f.isa.includes('APX') ? 30 : f.heading.startsWith('EVEX') ? 20 : f.heading.startsWith('VEX') || f.heading.startsWith('XOP') ? 10 : 0) + (/^66 (?!0F)/.test(f.heading) || /^66 0F (?:[0-9A-F]{2}\+| )/.test(f.heading) && f.syntax.some((x) => /\b(?:r16|m16|ax)\b/.test(x)) ? 2 : 0) + (f.isa.includes('i386') ? 1 : 0);
  const forms = [...entry.forms.values()]
    .sort((a, b) => rank(a) - rank(b))
    .slice(0, 16)
    .map((f) => ({ heading: f.heading, syntax: f.syntax.slice(0, 6), ...(f.isa.length ? { isa: f.isa } : {}), url: page ?? '' }));
  instructions[key] = {
    summary: old.summary ?? '',
    description: old.description ?? '',
    operation: old.operation ?? '',
    flags: entry.defs && entry.uses ? 'reads and sets EFLAGS' : entry.defs ? 'sets EFLAGS' : entry.uses ? 'reads EFLAGS' : 'none',
    category: old.category ?? '',
    group: old.group ?? groupOf(entry),
    forms,
  };
}
// One instruction per line, so a change shows as the lines of the instructions it touches.
const head = { about: 'x86 instructions (x86-64 and i386) as LLVM prints them, each with a description written for this project. Forms, encodings and extensions come from the X86 target of LLVM (tools/x86-index.mjs); the links lead to the HTML edition of Intel\'s manual.', source: `LLVM ${llvmVersion}`, docBase: 'https://www.felixcloutier.com/x86/' };
const lines = Object.entries(instructions).map(([key, e]) => `${JSON.stringify(key)}: ${JSON.stringify(e)}`);
writeFileSync(catalogPath, `${JSON.stringify(head, null, 1).slice(0, -2)},\n "instructions": {\n${lines.join(',\n')}\n }\n}\n`);
console.log(`src/data/x86-instructions.json: ${Object.keys(instructions).length} entries, ${Object.values(instructions).filter((e) => !e.summary).length} without a description`);

// For the catalogue and for debugging: the mnemonics and their forms.
const mnemonics = new Map();
for (let d = 1; d < n; d++) {
  const rec = records[names[d]];
  const t = templates[template[d]].replace(/\x01(.)(.)/g, (_, mi, m) => `{${printMethods[m.charCodeAt(0) - 65]}:${mi.charCodeAt(0) - 65}}`);
  const mnemonic = t.split('\t')[0];
  const entry = mnemonics.get(mnemonic) ?? { forms: [] };
  entry.forms.push({ llvm: names[d], asm: intelVariant(rec.AsmString ?? ''), predicates: (rec.Predicates ?? []).map(def), form: def(rec.Form), map: def(rec.OpMap), prefix: def(rec.OpPrefix), enc: def(rec.OpEnc), opcode: bitsValue(rec.Opcode) });
  mnemonics.set(mnemonic, entry);
}
writeFileSync(join(out, 'mnemonics.json'), JSON.stringify(Object.fromEntries([...mnemonics].sort((a, b) => a[0].localeCompare(b[0]))), null, 1));
writeFileSync(join(out, 'names.json'), JSON.stringify(names));
console.log(`src/core/x86/tables.ts, ${mnemonics.size} mnemonics (private/x86gen/mnemonics.json)`);
