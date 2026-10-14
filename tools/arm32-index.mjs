/**
 * Refreshes src/data/arm32-instructions.json — every AArch32 instruction an
 * Android armeabi-v7a library can hold, in A32 or T32 — from Arm's
 * machine-readable AArch32 ISA XML (developer.arm.com, "AArch32 ISA XML for
 * A-profile Architecture"). The forms, groups and links are rewritten; the
 * descriptions already in the file stay. A mnemonic new to the XML gets an
 * entry with empty text, which tests/data.mjs reports until someone writes it.
 *
 *   node tools/arm32-index.mjs <path to ISA_AArch32_xml_A_profile-YYYY-MM>
 *
 * As with tools/arm-index.mjs, only facts are taken from the XML: mnemonics,
 * the names of the forms ("ADD, ADDS (immediate)"), the instruction class,
 * which form is an alias of which, which instruction sets have an encoding
 * of it, and the assembler syntax templates. Arm's prose is under a notice
 * that forbids reproducing it, so none of it is copied: the descriptions are
 * our own words, and each form links to Arm's page for the authoritative text.
 *
 * A few mnemonics LLVM prints are not instructions of their own in the XML
 * (`trap` is a udf LLVM names, `hint` an unallocated hint); they are kept in
 * the file by hand and survive a refresh.
 */
import { existsSync } from 'node:fs';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { root } from './load.mjs';

const dir = process.argv[2];
if (!dir) {
  console.error('usage: node tools/arm32-index.mjs <ISA_AArch32_xml_A_profile-YYYY-MM directory>');
  process.exit(2);
}

const SOURCE = {
  forms: 'Arm AArch32 ISA XML for A-profile Architecture (developer.arm.com): mnemonics, form names, syntax templates, links',
  text: 'Descriptions written for this project; follow the links for the authoritative text',
};
const DOC_BASE = 'https://developer.arm.com/documentation/ddi0597/latest/';
const SECTION = { general: 'Base-Instructions', fpsimd: 'SIMD-FP-Instructions' };

/** Base instructions the reference lists as system ones: exceptions, modes, status registers, hints, barriers, coprocessors. */
const SYSTEM = new Set([
  'bkpt', 'cdp', 'cdp2', 'clrbhb', 'clrex', 'cps', 'cpsid', 'cpsie', 'csdb', 'dbg', 'dcps1', 'dcps2', 'dcps3', 'dmb', 'dsb', 'eret', 'esb', 'hint',
  'hlt', 'hvc', 'isb', 'ldc', 'ldc2', 'mcr', 'mcr2', 'mcrr', 'mcrr2', 'mrc', 'mrc2', 'mrrc', 'mrrc2', 'mrs', 'msr', 'nop', 'pssbb', 'rfe', 'rfeda',
  'rfedb', 'rfeia', 'rfeib', 'sb', 'setend', 'setpan', 'sev', 'sevl', 'smc', 'srs', 'srsda', 'srsdb', 'srsia', 'srsib', 'ssbb', 'stc', 'stc2', 'svc',
  'trap', 'tsb', 'udf', 'wfe', 'wfi', 'yield',
]);

const entity = (text) => text.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
const strip = (xml) => entity(xml.replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();
const first = (xml, pattern) => pattern.exec(xml)?.[1];

/** Arm's documentation site names a page after "<heading>: <brief>." with every other character a dash. */
const docUrl = (cls, heading, brief) => `${SECTION[cls]}/${`${heading}: ${brief}.`.replace(/[^A-Za-z0-9]/g, '-')}`;

/**
 * The mnemonics a syntax template's first word stands for, as LLVM prints them
 * without condition and qualifiers: `ADD{<c>}{<q>}` is add, `VADD{<c>}{<q>}.<dt>`
 * vadd, `LDM{IA}` ldm, `VFMA<bt>` vfmab and vfmat, `IT{<x>{<y>{<z>}}}` it.
 */
function mnemonicsOf(word) {
  let w = word.replace(/\{<c>\}|\{<q>\}|<c>|<q>/g, '');
  if (/^IT\{/.test(w)) return ['it'];
  if (w.includes('<bt>')) return ['B', 'T'].map((s) => w.replace('<bt>', s).split(/[.{]/)[0].toLowerCase());
  w = w.replace(/\{IA\}/, '');
  // VSEL has a page per condition it can test (VSELEQ, VSELGE…); LLVM prints them so too, and
  // they are one instruction.
  const name = w.split(/[.{]/)[0].toLowerCase().replace(/^vsel(eq|vs|ge|gt)$/, 'vsel');
  return /^[a-z][a-z0-9]*$/.test(name) ? [name] : [];
}

const files = (await readdir(dir)).filter((name) => name.endsWith('.xml') && !/^(encodingindex|shared_pseudocode|onebigfile|notice|.*index|.*encindex)\.xml$/.test(name));
const mnemonics = new Map();

for (const name of files.sort()) {
  const xml = await readFile(join(dir, name), 'utf8');
  const section = /<instructionsection id="([^"]+)"[^>]*type="(instruction|alias)"/.exec(xml);
  if (!section) continue;
  const [, id, type] = section;
  const cls = first(xml, /<docvar key="instr-class" value="([^"]+)"/);
  if (!SECTION[cls]) continue;
  const heading = strip(first(xml, /<heading>([\s\S]*?)<\/heading>/) ?? id);
  const brief = strip(first(xml, /<brief>([\s\S]*?)<\/brief>/) ?? '');
  const aliasOf = type === 'alias' ? strip(first(xml, /<aliasto[^>]*>([\s\S]*?)<\/aliasto>/) ?? '') : undefined;
  const vfp = /<docvar key="fpdatasize"/.test(xml) && !/<docvar key="simdvectorsize"/.test(xml);

  // One page can carry several mnemonics (ADD and ADDS; RFEDA, RFEDB…): the first word of each
  // syntax template names the one it is for. Which instruction sets have the encoding comes from
  // the encoding's own docvars.
  const perMnemonic = new Map();
  for (const [, attrs, body] of xml.matchAll(/<encoding name="([^"]+)"[^>]*>([\s\S]*?)<\/encoding>/g)) {
    const isa = first(body, /<docvar key="isa" value="([^"]+)"/) ?? (/_T\d/.test(attrs) ? 'T32' : 'A32');
    for (const [, template] of body.matchAll(/<asmtemplate[^>]*>([\s\S]*?)<\/asmtemplate>/g)) {
      const text = strip(template);
      const word = text.split(' ')[0];
      const syntax = text.replace(/^\S+/, (m) => m.toLowerCase());
      for (const mnemonic of mnemonicsOf(word)) {
        const entry = perMnemonic.get(mnemonic) ?? { syntax: [], isa: new Set() };
        if (!entry.syntax.includes(syntax)) entry.syntax.push(syntax);
        entry.isa.add(isa);
        perMnemonic.set(mnemonic, entry);
      }
    }
  }
  for (const [mnemonic, { syntax, isa }] of perMnemonic) {
    const entry = mnemonics.get(mnemonic) ?? { mnemonic, forms: [], groups: new Set() };
    entry.forms.push({ heading, ...(aliasOf ? { aliasOf } : {}), isa: ['A32', 'T32'].filter((s) => isa.has(s)), syntax, url: docUrl(cls, heading, brief) });
    entry.groups.add(cls === 'general' ? (SYSTEM.has(mnemonic) ? 'system' : 'base') : vfp ? 'fp' : 'simd');
    mnemonics.set(mnemonic, entry);
  }
}

// A mnemonic with forms in several groups (vmov, vcvt…) is filed under the first of these.
const ORDER = ['base', 'system', 'fp', 'simd'];
const sorted = [...mnemonics.values()].sort((a, b) => a.mnemonic.localeCompare(b.mnemonic));

const out = join(root, 'src', 'data', 'arm32-instructions.json');
const previous = existsSync(out) ? JSON.parse(await readFile(out, 'utf8')) : { instructions: {} };
const EMPTY = { summary: '', description: '', operation: '', flags: 'none', category: 'other' };
const instructions = {};
for (const entry of sorted) {
  const old = previous.instructions[entry.mnemonic] ?? EMPTY;
  const { summary, description, operation, flags, category } = { ...EMPTY, ...old };
  const group = ORDER.find((g) => entry.groups.has(g));
  instructions[entry.mnemonic] = { summary, description, operation, flags, category, group, forms: entry.forms };
}
// Entries the XML does not have (trap, hint) or no longer has stay: LLVM still prints them.
for (const [mnemonic, entry] of Object.entries(previous.instructions)) if (!instructions[mnemonic]) instructions[mnemonic] = entry;
const ordered = Object.fromEntries(Object.entries(instructions).sort(([a], [b]) => a.localeCompare(b)));
const catalog = {
  about: previous.about ?? 'Every AArch32 instruction (A32 and T32, base, floating point, Advanced SIMD, crypto): what it does in our words, its forms and syntax, a link to Arm\'s page. The conditions are those of src/data/arm64-instructions.json.',
  source: SOURCE,
  docBase: DOC_BASE,
  instructions: ordered,
};
await writeFile(out, `${JSON.stringify(catalog, null, 1)}\n`);
const missing = Object.keys(ordered).filter((m) => !ordered[m].description);
console.log(`${out}: ${Object.keys(ordered).length} mnemonics, ${sorted.reduce((n, e) => n + e.forms.length, 0)} forms, ${missing.length} without a description${missing.length ? `: ${missing.join(' ')}` : ''}`);
