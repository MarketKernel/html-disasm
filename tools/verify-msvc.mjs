/**
 * Checks the MSVC demangler (src/core/msvc.ts) against LLVM's llvm-undname:
 * every MSVC symbol of the given files is demangled here and by llvm-undname,
 * in full and with all of its --no-… options (the text the listing's short
 * names are made from), and the texts are compared.
 *
 *   node tools/verify-msvc.mjs <file …> [--show N]
 *   node tools/verify-msvc.mjs --symbols names.txt      one symbol per line
 *   … --vectors tests/fixtures/msvc-vectors.json         also keep verified examples
 *
 * The symbols of a file are the strings in it that look like MSVC names
 * (`?…@…`): a DLL's exports and imports, RTTI names, the names in a .lib.
 * LLVM's own tests of the demangler (llvm/test/Demangle/ms-*.test in an
 * LLVM checkout) are a good list too. Results fall in three groups: the same
 * text, not demangled here (kept as it is, which is safe), and different
 * text — the ones that matter.
 *
 * --vectors adds to a JSON file that tests/demangle.mjs checks without LLVM:
 * the shortest symbols that together hold every word and punctuation mark
 * llvm-undname printed, or with --all every symbol that came out the same
 * (for a list made to cover the grammar, such as LLVM's tests).
 *
 * Needs Homebrew's llvm@21 (llvm-undname).
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { load } from './load.mjs';

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const at = args.indexOf(name);
  if (at < 0) return fallback;
  const [value] = args.splice(at, 2).slice(1);
  return value;
};
const show = Number(option('--show', 4));
const symbolsFile = option('--symbols', null);
const vectorsFile = option('--vectors', null);
const all = args.includes('--all') && args.splice(args.indexOf('--all'), 1).length > 0;

const { undname, demangleMsvc } = await load('core/msvc');
const tool = '/opt/homebrew/opt/llvm@21/bin/llvm-undname';

const symbols = new Set();
if (symbolsFile) for (const line of readFileSync(symbolsFile, 'utf8').split('\n')) if (line.trim()) symbols.add(line.trim());
for (const file of args) {
  const text = readFileSync(file).toString('latin1');
  for (const m of text.matchAll(/[?.][\x21-\x7e]{3,}/g)) if (/^(\?|\.\?A)/.test(m[0]) && m[0].includes('@')) symbols.add(m[0]);
}
const list = [...symbols].filter((s) => !s.includes('\n'));
if (!list.length) {
  console.error('no MSVC symbols');
  process.exit(1);
}

/** llvm-undname over many names, one result per name ('' when it is invalid). */
function reference(names, flags) {
  // It exits with an error when any name is invalid; the output is still all there.
  const out = spawnSync(tool, flags, { input: names.join('\n') + '\n', encoding: 'latin1', maxBuffer: 1 << 30, stdio: ['pipe', 'pipe', 'ignore'] }).stdout;
  // Each name is echoed, then its demangling and a blank line — or, when it is invalid, only the blank line.
  const lines = out.split('\n');
  let at = 0;
  return names.map(() => {
    at++;
    const result = lines[at++] ?? '';
    if (result) at++;
    return result;
  });
}
const MINIMAL = ['--no-calling-convention', '--no-access-specifier', '--no-return-type', '--no-member-type', '--no-variable-type'];
const full = reference(list, []);
const minimal = reference(list, MINIMAL);

let same = 0;
let kept = 0;
let keptByThem = 0;
const wrong = [];
const missing = [];
const candidates = [];
for (let i = 0; i < list.length; i++) {
  const symbol = list[i];
  const theirs = { full: full[i], minimal: minimal[i] };
  const ours = { full: undname(symbol, 0), minimal: undname(symbol, 1 | 4 | 8 | 16 | 32) };
  if (!theirs.full) {
    keptByThem++;
    if (ours.full !== null) wrong.push({ symbol, ours, theirs: { full: '(invalid)', minimal: '' } });
    continue;
  }
  if (ours.full === null) {
    kept++;
    missing.push({ symbol, theirs });
    continue;
  }
  if (ours.full === theirs.full && ours.minimal === theirs.minimal) {
    same++;
    candidates.push([symbol, theirs.full, demangleMsvc(symbol).short]);
    continue;
  }
  wrong.push({ symbol, ours, theirs });
}

if (wrong.length) {
  console.log(`\ndifferent text: ${wrong.length}`);
  for (const { symbol, ours, theirs } of wrong.slice(0, show * 5)) {
    console.log(`  ${symbol}`);
    if (ours.full !== theirs.full) console.log(`    ours:   ${ours.full}\n    theirs: ${theirs.full}`);
    else console.log(`    ours (minimal):   ${ours.minimal}\n    theirs (minimal): ${theirs.minimal}`);
  }
}
if (missing.length) {
  console.log(`\nnot demangled here: ${missing.length}`);
  for (const { symbol, theirs } of missing.slice(0, show * 5)) console.log(`  ${symbol}\n    theirs: ${theirs.full}`);
}
console.log(`\n${list.length} symbols: ${same} the same, ${wrong.length} different, ${kept} not demangled here, ${keptByThem} not demangled by llvm-undname either`);

if (vectorsFile) {
  const vectors = existsSync(vectorsFile) ? JSON.parse(readFileSync(vectorsFile, 'utf8')) : [];
  const tokens = (text) => new Set(text.match(/[A-Za-z_]+|[^\sA-Za-z_0-9]/g) ?? []);
  const covered = new Set(vectors.flatMap(([, f]) => [...tokens(f)]));
  candidates.sort((a, b) => a[0].length - b[0].length);
  for (const vector of candidates) {
    // Words of the names themselves do not count, only what the demangler adds.
    const fresh = [...tokens(vector[1])].filter((t) => !covered.has(t) && !vector[0].includes(t));
    if (!fresh.length && !(all && !vectors.some(([v]) => v === vector[0]))) continue;
    fresh.forEach((t) => covered.add(t));
    vectors.push(vector);
  }
  writeFileSync(vectorsFile, JSON.stringify(vectors, null, 0).replace(/\],\[/g, '],\n['));
  console.log(`${vectors.length} vectors in ${vectorsFile}`);
}
