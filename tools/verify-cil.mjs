/**
 * Checks the CIL decoder against ildasm: every instruction of every method
 * body of an assembly is printed by the core, as the page shows it, and by
 * Microsoft's ildasm, and the two texts are compared, method by method (by
 * RVA) and instruction by instruction (by IL offset).
 *
 *   node tools/verify-cil.mjs [assembly.dll …] [--show N] [--only mnemonic]
 *   … --reference tests/fixtures/dotnet/hello.il   also write ildasm's text of the (one) assembly there
 *
 * ildasm's own line breaks are undone first: a signature's parameters, a
 * switch's targets and a long string's pieces (`"…" + "…"`) are joined on one
 * line, and a bytearray loses its comments, as the decoder writes them.
 * It is run with -bytes, which gives every method's RVA, and the bytes are
 * cut off again. Its output is cached in private/verify/cil/.
 *
 * ildasm comes from NuGet (runtime.osx-arm64.Microsoft.NETCore.ILDAsm, unzipped into private/ildasm),
 * or set ILDASM to the program.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { referenceLines } from './ildasm-text.mjs';
import { load, root } from './load.mjs';

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const at = args.indexOf(name);
  if (at < 0) return fallback;
  const [value] = args.splice(at, 2).slice(1);
  return value;
};
const show = Number(option('--show', 4));
const only = option('--only', null);
const referenceOut = option('--reference', null);
const files = args.length ? args : [join(root, 'tests', 'fixtures', 'dotnet', 'hello.dll')];
const ildasm = process.env.ILDASM ?? join(root, 'private', 'ildasm', 'pkg', 'runtimes', 'osx-arm64', 'native', 'ildasm');

const C = await load('core/pe', 'core/cil/program');
await C.loadEngine();

const cacheDir = join(root, 'private', 'verify', 'cil');
mkdirSync(cacheDir, { recursive: true });

function reference(bytes) {
  const hash = createHash('sha1').update(bytes).digest('hex').slice(0, 16);
  const text = join(cacheDir, `${hash}.il`);
  if (!existsSync(text)) {
    const input = join(cacheDir, `${hash}.dll`);
    writeFileSync(input, bytes);
    execFileSync(ildasm, ['-utf8', '-noca', '-bytes', `-out=${text}`, input], { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 30 });
  }
  return readFileSync(text, 'utf8');
}

let total = 0;
let same = 0;
const mismatches = new Map();
for (const file of files) {
  const bytes = new Uint8Array(readFileSync(file));
  let pe;
  try {
    pe = C.parsePe(bytes);
  } catch {
    pe = null;
  }
  if (!pe?.clr) {
    console.log(`${basename(file)}: not a .NET assembly, skipped`);
    continue;
  }
  let text;
  try {
    text = reference(bytes);
  } catch (err) {
    console.log(`${basename(file)}: ildasm failed (${err.message.split('\n')[0]}), skipped`);
    continue;
  }
  if (referenceOut) writeFileSync(referenceOut, text);
  const expected = referenceLines(text);
  const p = await C.analyzeCil(pe);
  const ours = new Map();
  p.functions.forEach((fn, f) => {
    const rva = p.method(f).rva;
    for (let i = fn.first; i < fn.first + fn.count; i++) {
      const insn = p.insn(i);
      ours.set(`${rva}:${insn.at}`, insn.text);
    }
  });
  p.dispose();
  let fileSame = 0;
  for (const [key, want] of expected) {
    const got = ours.get(key);
    const mnemonic = want.split(/\s/)[0];
    if (only && mnemonic !== only) continue;
    total++;
    if (got === want) {
      same++;
      fileSame++;
      continue;
    }
    const list = mismatches.get(mnemonic) ?? [];
    list.push({ file: basename(file), key, want, got });
    mismatches.set(mnemonic, list);
  }
  const missing = [...expected.keys()].filter((k) => !ours.has(k)).length;
  console.log(`${basename(file)}: ${expected.size} instructions in ildasm, ${ours.size} decoded, ${fileSame} the same${missing ? `, ${missing} not decoded here` : ''}`);
}

const sorted = [...mismatches].sort((a, b) => b[1].length - a[1].length);
for (const [mnemonic, list] of sorted) {
  console.log(`\n${mnemonic}: ${list.length} different`);
  for (const { file, key, want, got } of list.slice(0, show)) console.log(`  ${file} ${key}\n    ildasm: ${want}\n    ours:   ${got ?? '(none)'}`);
}
console.log(`\n${same} of ${total} instructions the same${total ? ` (${((same / total) * 100).toFixed(3)}%)` : ''}`);
process.exit(same === total ? 0 : 1);
