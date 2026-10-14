/**
 * The two JSON files the page explains things from:
 * src/data/arm64-instructions.json and src/data/hla64-words.json.
 * Every entry complete and well-formed; every mnemonic the decoder can print
 * has an entry; every word the HLA64 view uses is in the vocabulary; and no
 * description carries Arm's boilerplate, a sign of text copied from the
 * specification (which its notice does not allow).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const { check, done } = checker();
const C = await load('core/catalog', 'core/arm64/decode');
const catalog = JSON.parse(readFileSync(join(root, 'src', 'data', 'arm64-instructions.json'), 'utf8'));
const words = JSON.parse(readFileSync(join(root, 'src', 'data', 'hla64-words.json'), 'utf8'));

const CATEGORIES = new Set(['variable', 'structure', 'memory', 'table', 'reference', 'aggregate', 'exception', 'arithmetic', 'logic', 'shift', 'bitfield', 'move', 'compare', 'branch', 'call', 'load', 'store', 'atomic', 'barrier', 'system', 'pointer-auth', 'fp-arith', 'fp-convert', 'fp-compare', 'fp-move', 'simd-arith', 'simd-logic', 'simd-compare', 'simd-shift', 'simd-permute', 'simd-load-store', 'simd-reduce', 'simd-convert', 'simd-move', 'crypto', 'memory-copy', 'hint', 'other']);
const FLAGS = new Set(['none', 'sets NZCV', 'reads NZCV', 'reads and sets NZCV', 'sets QC']);
const GROUPS = new Set(['base', 'fp', 'simd', 'system']);

const problems = [];
for (const [mnemonic, e] of Object.entries(catalog.instructions)) {
  if (!/^[a-z][a-z0-9.]*$/.test(mnemonic)) problems.push(`${mnemonic}: odd mnemonic`);
  if (!e.summary?.trim() || e.summary.length > 60) problems.push(`${mnemonic}: summary`);
  if (!e.description?.trim() || e.description.length < 20) problems.push(`${mnemonic}: description`);
  if (typeof e.operation !== 'string') problems.push(`${mnemonic}: operation`);
  if (!FLAGS.has(e.flags)) problems.push(`${mnemonic}: flags ${e.flags}`);
  if (!CATEGORIES.has(e.category)) problems.push(`${mnemonic}: category ${e.category}`);
  if (!GROUPS.has(e.group)) problems.push(`${mnemonic}: group ${e.group}`);
  if (!e.forms?.length || e.forms.some((f) => !f.heading || !f.url || !Array.isArray(f.syntax))) problems.push(`${mnemonic}: forms`);
  if (/\bThis instruction\b|\bencoded in the\b/.test(e.description)) problems.push(`${mnemonic}: reads like the specification`);
}
check('catalogue entries well-formed', problems, []);
check('catalogue size', Object.keys(catalog.instructions).length > 1100, true);
check('16 conditions', Object.keys(catalog.conditions).length, 16);

// Every mnemonic the decoder prints, over the fixed vectors, has an entry.
const { vectors } = JSON.parse(readFileSync(join(root, 'tests', 'fixtures', 'decode-vectors.json'), 'utf8'));
const missing = new Set();
for (const [word, pc] of vectors) {
  const insn = C.decode(parseInt(word, 16), parseInt(pc, 16));
  if (insn.m !== '.inst' && !C.lookup(insn.m)) missing.add(insn.m);
}
check('every printed mnemonic is in the catalogue', [...missing].sort(), []);
check('b.ne finds b.cond', C.lookup('b.ne')?.summary, catalog.instructions['b.cond'].summary);

// The HLA64 vocabulary.
const ids = words.words.map((w) => w.id);
check('word ids unique', ids.length, new Set(ids).size);
check('word status', words.words.filter((w) => w.status !== 'hla64' && w.status !== 'new').map((w) => w.id), []);
check('words complete', words.words.filter((w) => !w.syntax || !w.description || !w.category || typeof w.example !== 'string').map((w) => w.id), []);
check('words name real instructions', words.words.flatMap((w) => w.instructions.filter((m) => !C.lookup(m)).map((m) => `${w.id}: ${m}`)), []);
const used = new Set();
for (const file of ['src/core/hla.ts', 'src/app/render.ts', 'src/app/cards.ts', 'src/core/wasm/hla.ts', 'src/app/wasm.ts', 'src/core/x86/hla.ts', 'src/core/cil/hla.ts', 'src/app/cil.ts', 'src/core/jvm/hla.ts', 'src/app/jvm.ts']) {
  const code = readFileSync(join(root, file), 'utf8');
  for (const [, id] of code.matchAll(/words\.push\(([^)]*)\)/g)) for (const [, w] of id.matchAll(/(?<!=== )'([a-z0-9-]+)'/g)) used.add(w);
  for (const [, id] of code.matchAll(/\['[a-z_0-9]+', '([a-z0-9-]+)'\]/g)) used.add(id);
  for (const [, id] of code.matchAll(/\[\s*'[^']*',\s*\d+,\s*'([a-z0-9-]+)'\]/g)) used.add(id);
  for (const [, id] of code.matchAll(/wordTip\('([a-z0-9-]+)'\)/g)) used.add(id);
}
check('every word the view uses is in the vocabulary', [...used].filter((id) => !ids.includes(id)).sort(), []);

check('word targets', words.words.filter((w) => !Array.isArray(w.targets) || !w.targets.length || w.targets.some((t) => t !== 'arm64' && t !== 'wasm' && t !== 'x86' && t !== 'cil' && t !== 'jvm')).map((w) => w.id), []);
check('x86 words', words.words.filter((w) => w.targets?.includes('x86') && (!Array.isArray(w.x86) || typeof w.x86Example !== 'string')).map((w) => w.id), []);

// The WebAssembly catalogue: an entry for every instruction the decoder knows, and nothing else.
const wasm = JSON.parse(readFileSync(join(root, 'src', 'data', 'wasm-instructions.json'), 'utf8'));
const wasmRu = JSON.parse(readFileSync(join(root, 'src', 'data', 'wasm-instructions.ru.json'), 'utf8'));
const O = await load('core/wasm/opcodes', 'core/catalog');
const opNames = [...new Set(O.allOps().map((op) => op.name))].sort();
check('wasm: an entry per instruction', Object.keys(wasm.instructions).sort(), opNames);
const wasmProblems = [];
for (const [name, e] of Object.entries(wasm.instructions)) {
  if (!e.summary?.trim() || e.summary.length > 60) wasmProblems.push(`${name}: summary`);
  if (!e.description?.trim() || e.description.length < 20) wasmProblems.push(`${name}: description`);
  if (!e.operation?.trim()) wasmProblems.push(`${name}: operation`);
  if (!CATEGORIES.has(e.category)) wasmProblems.push(`${name}: category ${e.category}`);
  if (/\bThis instruction\b|\bencoded in the\b|\bvalidation\b/i.test(e.description)) wasmProblems.push(`${name}: reads like the specification`);
}
check('wasm: entries well-formed', wasmProblems, []);
check('wasm: every entry has forms and a link', opNames.filter((m) => !O.WASM_CATALOGUE.lookup(m)?.forms.every((f) => f.url.startsWith('https://'))), []);
check('wasm words name real instructions', words.words.flatMap((w) => (w.wasm ?? []).filter((m) => !O.WASM_CATALOGUE.lookup(m)).map((m) => `${w.id}: ${m}`)), []);
check('wasm words', words.words.filter((w) => w.targets?.includes('wasm') && !Array.isArray(w.wasm)).map((w) => w.id), []);
check('ru: same wasm instructions', Object.keys(wasmRu.instructions).sort(), opNames);
check('ru: wasm texts', Object.entries(wasmRu.instructions).filter(([, e]) => !/[а-яё]/i.test(e.summary + e.description) || e.summary.length > 100 || e.description.length < 15).map(([k]) => k), []);

// The CIL catalogue: an entry for every opcode of src/core/cil/opcodes.ts, and nothing else.
const cil = JSON.parse(readFileSync(join(root, 'src', 'data', 'cil-instructions.json'), 'utf8'));
const cilRu = JSON.parse(readFileSync(join(root, 'src', 'data', 'cil-instructions.ru.json'), 'utf8'));
const CO = await load('core/cil/opcodes', 'core/catalog');
const cilNames = CO.allOps().map((op) => op.name).sort();
check('cil: an entry per opcode', Object.keys(cil.instructions).sort(), cilNames);
const cilProblems = [];
for (const [name, e] of Object.entries(cil.instructions)) {
  if (!e.summary?.trim() || e.summary.length > 60) cilProblems.push(`${name}: summary`);
  if (!e.description?.trim() || e.description.length < 20) cilProblems.push(`${name}: description`);
  if (!e.operation?.trim()) cilProblems.push(`${name}: operation`);
  if (typeof e.doc !== 'string' || (e.doc && !/^[A-Z][A-Za-z0-9_]*$/.test(e.doc))) cilProblems.push(`${name}: doc`);
  if (/\bThis instruction\b|\bencoded in the\b|\bverifiable\b/i.test(e.description)) cilProblems.push(`${name}: reads like the specification`);
}
check('cil: entries well-formed', cilProblems, []);
check('cil: categories known', CO.allOps().filter((op) => !CATEGORIES.has(op.category) && !['constant', 'conversion', 'object', 'array', 'stack', 'prefix'].includes(op.category)).map((op) => op.name), []);
check('cil words name real instructions', words.words.flatMap((w) => (w.cil ?? []).filter((m) => !CO.CIL_CATALOGUE.lookup(m)).map((m) => `${w.id}: ${m}`)), []);
check('cil words', words.words.filter((w) => w.targets?.includes('cil') && (!Array.isArray(w.cil) || typeof w.cilExample !== 'string')).map((w) => w.id), []);
check('cil: every entry has forms and a link', cilNames.filter((m) => !CO.CIL_CATALOGUE.lookup(m)?.forms.every((f) => f.url.startsWith('https://'))), []);
check('ru: same cil instructions', Object.keys(cilRu.instructions).sort(), cilNames);
check('ru: cil texts', Object.entries(cilRu.instructions).filter(([, e]) => !/[а-яё]/i.test(e.summary + e.description) || e.summary.length > 100 || e.description.length < 15).map(([k]) => k), []);

// The JVM catalogue: an entry for every mnemonic javap prints (src/core/jvm/opcodes.ts), and nothing else.
const jvm = JSON.parse(readFileSync(join(root, 'src', 'data', 'jvm-instructions.json'), 'utf8'));
const jvmRu = JSON.parse(readFileSync(join(root, 'src', 'data', 'jvm-instructions.ru.json'), 'utf8'));
const JO = await load('core/jvm/opcodes', 'core/catalog');
const jvmNames = JO.allOps().map((op) => op.name).sort();
check('jvm: an entry per opcode', Object.keys(jvm.instructions).sort(), jvmNames);
const jvmProblems = [];
for (const [name, e] of Object.entries(jvm.instructions)) {
  if (!e.summary?.trim() || e.summary.length > 60) jvmProblems.push(`${name}: summary`);
  if (!e.description?.trim() || e.description.length < 20) jvmProblems.push(`${name}: description`);
  if (!e.operation?.trim()) jvmProblems.push(`${name}: operation`);
  if (!/^[a-z0-9_]+$/.test(e.doc ?? '')) jvmProblems.push(`${name}: doc`);
  if (/The index is an unsigned|must be of type|is undefined|linkage exception/i.test(e.description)) jvmProblems.push(`${name}: reads like the specification`);
}
check('jvm: entries well-formed', jvmProblems, []);
check('jvm: categories known', JO.allOps().filter((op) => !CATEGORIES.has(op.category) && !['constant', 'conversion', 'object', 'array', 'stack'].includes(op.category)).map((op) => op.name), []);
check('jvm words name real instructions', words.words.flatMap((w) => (w.jvm ?? []).filter((m) => !JO.JVM_CATALOGUE.lookup(m)).map((m) => `${w.id}: ${m}`)), []);
check('jvm words', words.words.filter((w) => w.targets?.includes('jvm') && (!Array.isArray(w.jvm) || typeof w.jvmExample !== 'string')).map((w) => w.id), []);
check('jvm: every entry has forms and a link', jvmNames.filter((m) => !JO.JVM_CATALOGUE.lookup(m)?.forms.every((f) => f.url.startsWith('https://docs.oracle.com/javase/specs/jvms/'))), []);
check('ru: same jvm instructions', Object.keys(jvmRu.instructions).sort(), jvmNames);
check('ru: jvm texts', Object.entries(jvmRu.instructions).filter(([, e]) => !/[а-яё]/i.test(e.summary + e.description) || e.summary.length > 100 || e.description.length < 15).map(([k]) => k), []);

// The AArch32 catalogue: well-formed, and an entry for every mnemonic the decoder prints.
const arm32 = JSON.parse(readFileSync(join(root, 'src', 'data', 'arm32-instructions.json'), 'utf8'));
const arm32Ru = JSON.parse(readFileSync(join(root, 'src', 'data', 'arm32-instructions.ru.json'), 'utf8'));
const ARM32_FLAGS = new Set([...FLAGS, 'sets Q', 'sets GE', 'reads GE']);
const ARM32_CATEGORIES = new Set([...CATEGORIES, 'coprocessor', 'parallel']);
const arm32Problems = [];
for (const [mnemonic, e] of Object.entries(arm32.instructions)) {
  if (!/^[a-z][a-z0-9]*$/.test(mnemonic)) arm32Problems.push(`${mnemonic}: odd mnemonic`);
  if (!e.summary?.trim() || e.summary.length > 60) arm32Problems.push(`${mnemonic}: summary`);
  if (!e.description?.trim() || e.description.length < 20) arm32Problems.push(`${mnemonic}: description`);
  if (typeof e.operation !== 'string' || !e.operation) arm32Problems.push(`${mnemonic}: operation`);
  if (!ARM32_FLAGS.has(e.flags)) arm32Problems.push(`${mnemonic}: flags ${e.flags}`);
  if (!ARM32_CATEGORIES.has(e.category)) arm32Problems.push(`${mnemonic}: category ${e.category}`);
  if (!GROUPS.has(e.group)) arm32Problems.push(`${mnemonic}: group ${e.group}`);
  if (!e.forms?.length || e.forms.some((f) => !f.heading || !f.url || !Array.isArray(f.syntax) || !f.isa?.length)) arm32Problems.push(`${mnemonic}: forms`);
  if (/\bThis instruction\b|\bencoded in the\b/.test(e.description)) arm32Problems.push(`${mnemonic}: reads like the specification`);
}
check('arm32: entries well-formed', arm32Problems, []);
check('arm32: catalogue size', Object.keys(arm32.instructions).length > 450, true);
const A = await load('core/arm32/decode', 'core/arm32/types', 'core/catalog');
const arm32Vectors = JSON.parse(readFileSync(join(root, 'tests', 'fixtures', 'arm32-vectors.json'), 'utf8')).vectors;
const arm32Missing = new Set();
for (const [encoding, pc, , wide] of arm32Vectors) {
  const value = parseInt(encoding, 16) >>> 0;
  const insn = encoding.length === 8 && !wide ? A.decodeArm(value, parseInt(pc, 16)) : wide ? A.decodeThumb(value >>> 16, value & 0xffff, 0) : A.decodeThumb(value, 0, 0);
  if (!insn.m.startsWith('.') && !A.ARM32_CATALOGUE.lookup(insn.m)) arm32Missing.add(insn.m);
}
check('arm32: every printed mnemonic is in the catalogue', [...arm32Missing].sort(), []);
check('arm32: keys', ['bne', 'bl', 'blls', 'ldr.w', 'vaddeq.f32', 'itte', 'vmovls.f32', 'addseq', 'vseleq.f32', 'ldrhs'].map(A.arm32Key), ['b', 'bl', 'bl', 'ldr', 'vadd', 'it', 'vmov', 'adds', 'vsel', 'ldr']);
check('arm32: without the condition', ['addeq', 'vaddeq.f32', 'bne', 'itte', 'ldr'].map(A.arm32Unconditional), ['add', 'vadd.f32', 'b', 'itte', 'ldr']);
check('ru: same arm32 instructions', Object.keys(arm32Ru.instructions).sort(), Object.keys(arm32.instructions).sort());
check('ru: arm32 texts', Object.entries(arm32Ru.instructions).filter(([, e]) => !/[а-яё]/i.test(e.summary + e.description) || !e.summary.trim() || e.summary.length > 100 || e.description.length < 15).map(([k]) => k), []);

// The x86 catalogue: well-formed, and an entry for every mnemonic the decoder prints.
const x86 = JSON.parse(readFileSync(join(root, 'src', 'data', 'x86-instructions.json'), 'utf8'));
const x86Ru = JSON.parse(readFileSync(join(root, 'src', 'data', 'x86-instructions.ru.json'), 'utf8'));
const X86_FLAGS = new Set(['none', 'sets EFLAGS', 'reads EFLAGS', 'reads and sets EFLAGS']);
const X86_CATEGORIES = new Set([...CATEGORIES, 'stack', 'flags', 'prefix', 'tile']);
const X86_GROUPS = new Set(['base', 'x87', 'simd', 'system']);
const x86Problems = [];
for (const [mnemonic, e] of Object.entries(x86.instructions)) {
  if (!/^[a-z0-9_.{}]+$/.test(mnemonic)) x86Problems.push(`${mnemonic}: odd mnemonic`);
  if (!e.summary?.trim() || e.summary.length > 60) x86Problems.push(`${mnemonic}: summary`);
  if (!e.description?.trim() || e.description.length < 20) x86Problems.push(`${mnemonic}: description`);
  if (typeof e.operation !== 'string' || !e.operation) x86Problems.push(`${mnemonic}: operation`);
  if (!X86_FLAGS.has(e.flags)) x86Problems.push(`${mnemonic}: flags ${e.flags}`);
  if (!X86_CATEGORIES.has(e.category)) x86Problems.push(`${mnemonic}: category ${e.category}`);
  if (!X86_GROUPS.has(e.group)) x86Problems.push(`${mnemonic}: group ${e.group}`);
  if (!e.forms?.length || e.forms.some((f) => !f.heading || typeof f.url !== 'string' || !Array.isArray(f.syntax) || !f.syntax.length)) x86Problems.push(`${mnemonic}: forms`);
  if (/\bThis instruction\b|\bencoded in the\b/.test(e.description)) x86Problems.push(`${mnemonic}: reads like the specification`);
}
check('x86: entries well-formed', x86Problems, []);
check('x86: catalogue size', Object.keys(x86.instructions).length > 1700, true);
const X = await load('core/x86/decode', 'core/x86/print', 'core/catalog');
await X.loadX86();
const x86Missing = new Set();
for (const [bytes, addr, , mode] of JSON.parse(readFileSync(join(root, 'tests', 'fixtures', 'x86-vectors.json'), 'utf8')).vectors) {
  const code = Uint8Array.from(bytes.match(/../g).map((b) => parseInt(b, 16)));
  const printed = X.printX86(X.decodeX86(code, 0, code.length, parseInt(addr, 16), mode ?? 64));
  if (printed.m !== '<unknown>' && !X.X86_CATALOGUE.lookup(printed.m)) x86Missing.add(printed.m);
}
check('x86: every printed mnemonic is in the catalogue', [...x86Missing].sort(), []);
check('x86: keys', ['jne', 'cmovge', 'sete', 'cmpltps', 'vcmpnle_uqpd', 'vpcmpgtd', 'vpcmpequb', 'vpcomltub', 'add', 'vpcmpeqd'].map(X.x86Key), ['jcc', 'cmovcc', 'setcc', 'cmpps', 'vcmppd', 'vpcmpgtd', 'vpcmpub', 'vpcomub', 'add', 'vpcmpeqd']);
check('x86 words name real instructions', words.words.flatMap((w) => (w.x86 ?? []).filter((m) => !X.X86_CATALOGUE.lookup(m)).map((m) => `${w.id}: ${m}`)), []);
check('x86: links to the manual pages', Object.entries(x86.instructions).filter(([, e]) => e.forms[0].url).length > 1300, true);
check('ru: same x86 instructions', Object.keys(x86Ru.instructions).sort(), Object.keys(x86.instructions).sort());
check('ru: x86 texts', Object.entries(x86Ru.instructions).filter(([, e]) => !/[а-яё]/i.test(e.summary + e.description) || !e.summary.trim() || e.summary.length > 100 || e.description.length < 15).map(([k]) => k), []);

// Russian: every instruction, condition and word has its text; the lookup follows the language.
const catalogRu = JSON.parse(readFileSync(join(root, 'src', 'data', 'arm64-instructions.ru.json'), 'utf8'));
const wordsRu = JSON.parse(readFileSync(join(root, 'src', 'data', 'hla64-words.ru.json'), 'utf8'));
const cyrillic = /[а-яё]/i;
check('ru: same instructions', Object.keys(catalogRu.instructions).sort(), Object.keys(catalog.instructions).sort());
check('ru: instruction texts', Object.entries(catalogRu.instructions).filter(([, e]) => !cyrillic.test(e.summary + e.description) || !e.summary.trim() || !e.description.trim() || e.summary.length > 100).map(([k]) => k), []);
check('ru: conditions', Object.keys(catalogRu.conditions).sort(), Object.keys(catalog.conditions).sort());
check('ru: words', Object.keys(wordsRu.words).sort(), [...ids].sort());
check('ru: word texts', Object.entries(wordsRu.words).filter(([, w]) => !cyrillic.test(w.description) || !cyrillic.test(w.category)).map(([k]) => k), []);
const L = await load('core/catalog', 'core/i18n');
L.setLanguage('ru');
check('ru: lookup', L.lookup('b.ne').summary, catalogRu.instructions['b.cond'].summary);
check('ru: forms stay', L.lookup('add').forms.length, catalog.instructions.add.forms.length);
check('ru: conditions', L.conditions().lt.name, catalogRu.conditions.lt.name);
check('ru: words', L.word('udiv').description, wordsRu.words.udiv.description);
check('ru: wasm lookup', L.WASM_CATALOGUE.lookup('i32.add').summary, wasmRu.instructions['i32.add'].summary);
check('ru: arm32 lookup', L.ARM32_CATALOGUE.lookup('bne').summary, arm32Ru.instructions.b.summary);
check('ru: x86 lookup', L.X86_CATALOGUE.lookup('jne').summary, x86Ru.instructions.jcc.summary);
L.setLanguage('en');
check('en again', L.lookup('add').summary, catalog.instructions.add.summary);

done('data');
