/**
 * Refreshes src/data/arm64-instructions.json — every A64 instruction the
 * disassembler can meet in a macOS program — from Arm's machine-readable
 * A64 ISA XML (developer.arm.com, "A64 ISA XML for A-profile Architecture").
 * The forms, groups and links are rewritten; the descriptions already in the
 * file stay. A mnemonic new to the XML gets an entry with empty text, which
 * tests/data.mjs reports until someone writes it.
 *
 *   node tools/arm-index.mjs <path to ISA_A64_xml_A_profile-YYYY-MM>
 *
 * Only facts are taken from the XML: mnemonics, the names of the forms
 * ("ADD (immediate)"), the instruction class, which form is an alias of which,
 * and the assembler syntax templates. Arm's prose is under a proprietary
 * notice that forbids reproducing it, so none of it is copied: the
 * descriptions are our own words, and each form links to Arm's page for the
 * authoritative text.
 *
 * SVE and SME are left out: macOS user code does not run SVE, and the
 * decoder shows SME streaming code as raw words.
 */
import { existsSync } from 'node:fs';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { root } from './load.mjs';

const dir = process.argv[2];
if (!dir) {
  console.error('usage: node tools/arm-index.mjs <ISA_A64_xml_A_profile-YYYY-MM directory>');
  process.exit(2);
}

const CLASSES = new Set(['general', 'system', 'float', 'fpsimd', 'advsimd']);
const SECTION = { general: 'Base-Instructions', system: 'Base-Instructions', float: 'SIMD-FP-Instructions', fpsimd: 'SIMD-FP-Instructions', advsimd: 'SIMD-FP-Instructions' };
const GROUP = { general: 'base', system: 'system', float: 'fp', fpsimd: 'fp', advsimd: 'simd' };

const SOURCE = {
  forms: 'Arm A64 ISA XML for A-profile Architecture (developer.arm.com): mnemonics, form names, syntax templates, links',
  text: 'Descriptions written for this project; follow the links for the authoritative text',
};

const entity = (text) => text.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
const strip = (xml) => entity(xml.replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();
const first = (xml, pattern) => pattern.exec(xml)?.[1];

/**
 * Arm's documentation site names a page after "<heading>: <brief>." with every other character a
 * dash. The file keeps the path after DOC_BASE; the app puts the two together.
 */
const DOC_BASE = 'https://developer.arm.com/documentation/ddi0602/latest/';
const docUrl = (cls, heading, brief) => `${SECTION[cls]}/${`${heading}: ${brief}.`.replace(/[^A-Za-z0-9]/g, '-')}`;

const files = (await readdir(dir)).filter((name) => name.endsWith('.xml') && !/^(encodingindex|shared_pseudocode|onebigfile|notice|.*index)\.xml$/.test(name));
const mnemonics = new Map();

for (const name of files.sort()) {
  const xml = await readFile(join(dir, name), 'utf8');
  const section = /<instructionsection id="([^"]+)"[^>]*type="(instruction|alias)"/.exec(xml);
  if (!section) continue;
  const [, id, type] = section;
  // One page (LDRAA, LDRAB) has no class at all; it is a base instruction.
  const cls = first(xml, /<docvar key="instr-class" value="([^"]+)"/) ?? (first(xml, /<docvar key="isa" value="([^"]+)"/) === 'A64' ? 'general' : undefined);
  if (!CLASSES.has(cls)) continue;
  const heading = strip(first(xml, /<heading>([\s\S]*?)<\/heading>/) ?? id);
  const brief = strip(first(xml, /<brief>([\s\S]*?)<\/brief>/) ?? '');
  const aliasOf = type === 'alias' ? strip(first(xml, /<aliasto[^>]*>([\s\S]*?)<\/aliasto>/) ?? '') : undefined;

  // One file can carry several mnemonics (LDADD, LDADDA, LDADDAL, LDADDL): the first word of each
  // syntax template is the mnemonic as it is printed. B.<cond> is filed as b.cond, SMULL{2} as both
  // smull and smull2 (the "2" forms work on the upper half of the vector).
  const perMnemonic = new Map();
  for (const [, body] of xml.matchAll(/<encoding name="[^"]+"[^>]*>([\s\S]*?)<\/encoding>/g)) {
    for (const [, template] of body.matchAll(/<asmtemplate>([\s\S]*?)<\/asmtemplate>/g)) {
      const text = strip(template);
      const word = text.split(' ')[0].toLowerCase().replace('<cond>', 'cond');
      const syntax = text.replace(/^\S+/, (m) => m.toLowerCase());
      const names = word.endsWith('{2}') ? [word.slice(0, -3), `${word.slice(0, -3)}2`] : [word];
      for (const mnemonic of names) {
        if (!/^[a-z][a-z0-9.]*$/.test(mnemonic)) continue;
        const list = perMnemonic.get(mnemonic) ?? [];
        if (!list.includes(syntax)) list.push(syntax);
        perMnemonic.set(mnemonic, list);
      }
    }
  }
  if (!perMnemonic.size) {
    const mnemonic = (first(xml, /<docvar key="alias_mnemonic" value="([^"]+)"/) ?? first(xml, /<docvar key="mnemonic" value="([^"]+)"/) ?? '').toLowerCase();
    if (mnemonic) perMnemonic.set(mnemonic, []);
  }

  for (const [mnemonic, syntax] of perMnemonic) {
    const key = mnemonic;
    const entry = mnemonics.get(key) ?? { mnemonic: key, group: GROUP[cls], forms: [], classes: new Set() };
    entry.forms.push({ heading, ...(aliasOf ? { aliasOf } : {}), syntax, url: docUrl(cls, heading, brief) });
    entry.classes.add(cls);
    mnemonics.set(key, entry);
  }
}

const sorted = [...mnemonics.values()].sort((a, b) => a.mnemonic.localeCompare(b.mnemonic));
for (const entry of sorted) {
  // A mnemonic with a base form and a SIMD one (mov, umull…) is filed under the base.
  const groups = new Set([...entry.classes].map((cls) => GROUP[cls]));
  entry.group = ['base', 'fp', 'system', 'simd'].find((group) => groups.has(group)) ?? entry.group;
}

const out = join(root, 'src', 'data', 'arm64-instructions.json');
const previous = existsSync(out) ? JSON.parse(await readFile(out, 'utf8')) : { instructions: {} };
const EMPTY = { summary: '', description: '', operation: '', flags: 'none', category: 'other' };
const instructions = {};
for (const entry of sorted) {
  const old = previous.instructions[entry.mnemonic] ?? EMPTY;
  const { summary, description, operation, flags, category } = { ...EMPTY, ...old };
  instructions[entry.mnemonic] = { summary, description, operation, flags, category, group: entry.group, forms: entry.forms };
}
// Entries the XML no longer has (Arm withdrew TME's tcancel, for one) stay: old programs still contain them.
for (const [mnemonic, entry] of Object.entries(previous.instructions)) if (!instructions[mnemonic]) instructions[mnemonic] = entry;
const ordered = Object.fromEntries(Object.entries(instructions).sort(([a], [b]) => a.localeCompare(b)));
const catalog = { ...previous, source: SOURCE, docBase: DOC_BASE, instructions: ordered };
await writeFile(out, `${JSON.stringify(catalog, null, 1)}\n`);
const missing = Object.keys(ordered).filter((m) => !ordered[m].description);
console.log(`${out}: ${Object.keys(ordered).length} mnemonics, ${sorted.reduce((n, e) => n + e.forms.length, 0)} forms, ${missing.length} without a description${missing.length ? `: ${missing.join(' ')}` : ''}`);
