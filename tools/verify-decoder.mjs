/**
 * Checks the decoder against LLVM: every instruction of a program's
 * __TEXT,__text is decoded here and by llvm-objdump (from Xcode), and the
 * two texts are compared.
 *
 *   node tools/verify-decoder.mjs <program> [--show N] [--only mnemonic]
 *       (a Mach-O program, an arm64 ELF library or an arm64 Windows program: its .text)
 *   node tools/verify-decoder.mjs --random 1000000 [--seed 1]
 *   … --vectors tests/fixtures/decode-vectors.json   also keep verified examples
 *
 * The code is wrapped in an ELF file first (tools/elf-wrap.mjs), so that
 * llvm-objdump prints the generic Arm syntax rather than Apple's. LLVM's
 * output is cached in private/verify/ by the program's size and mtime.
 * Mismatches are grouped by LLVM's mnemonic, most frequent first, with a few
 * examples each.
 *
 * --random checks words a real program may never contain: random encodings
 * outside SVE and SME (which the decoder leaves alone). Where LLVM names an
 * instruction that we print as .inst, it is counted apart as "not decoded";
 * where both decode it differently, it is a mismatch.
 *
 * --vectors adds to a JSON file one matching example per shape of line (the
 * text with its numbers blanked out): tests/decode.mjs checks them without
 * needing Xcode.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { elfWrap } from './elf-wrap.mjs';
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
const random = Number(option('--random', 0));
const vectorsFile = option('--vectors', null);
const seed = Number(option('--seed', 1));
const program = args[0];
if (!random && !program) {
  console.error('usage: node tools/verify-decoder.mjs <program> | --random N [--seed S]');
  process.exit(2);
}

const { parseMachO, isElf, parseElf, isPe, parsePe, decode, formatInsn } = await load('core/macho', 'core/elf', 'core/pe', 'core/arm64/decode', 'core/arm64/types');

let code;
let text;
let cacheName;
if (random) {
  // xorshift32: the same seed gives the same words, so LLVM's output can be cached.
  let state = seed >>> 0 || 1;
  const next = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
  const words = new Uint32Array(random);
  for (let i = 0; i < random; ) {
    const word = next();
    const op1 = (word >>> 25) & 0xf;
    if (op1 === 0 || op1 === 2 || op1 === 1 || op1 === 3) continue; // reserved, SME, SVE
    words[i++] = word;
  }
  code = new Uint8Array(words.buffer);
  text = { addr: 0x100000000 };
  cacheName = `random-${random}-${seed}.txt`;
} else {
  const file = readFileSync(program);
  const bytes = new Uint8Array(file.buffer, file.byteOffset, file.length);
  if (isElf(bytes)) {
    // An Android or Linux arm64 library: its .text, as the same wrapper presents it.
    const elf = parseElf(bytes);
    text = elf.sections.find((s) => s.name === '.text');
    if (!text) throw new Error('no .text');
  } else if (isPe(bytes)) {
    // Windows on Arm: the first code section (.text), at its address in memory.
    const pe = parsePe(bytes);
    const section = pe.sections.find((s) => s.name === '.text') ?? pe.sections.find((s) => s.flags & 0x20000000);
    if (!section) throw new Error('no .text');
    text = { addr: pe.imageBase + section.rva, offset: section.rawOffset, size: Math.min(section.virtualSize, section.rawSize) };
  } else {
    const image = parseMachO(bytes);
    text = image.sections.find((s) => s.segname === '__TEXT' && s.sectname === '__text');
    if (!text) throw new Error('no __TEXT,__text');
  }
  code = bytes.subarray(text.offset, text.offset + text.size);
  const stamp = statSync(program);
  cacheName = `${basename(program)}-${stamp.size}-${Math.floor(stamp.mtimeMs)}.txt`;
}

const objdump = (() => {
  try {
    return execFileSync('xcrun', ['--find', 'llvm-objdump'], { encoding: 'utf8' }).trim();
  } catch {
    return 'llvm-objdump';
  }
})();

const cacheDir = join(root, 'private', 'verify');
mkdirSync(cacheDir, { recursive: true });
const cache = join(cacheDir, cacheName);
if (!existsSync(cache)) {
  const elf = join(cacheDir, 'text.o');
  writeFileSync(elf, elfWrap(code, text.addr));
  console.log(`llvm-objdump on ${(code.length / 4).toLocaleString()} instructions…`);
  const out = execFileSync(objdump, ['-d', '-z', '--mattr=+all', '--no-show-raw-insn', elf], { encoding: 'utf8', maxBuffer: 1 << 30 });
  writeFileSync(cache, out);
}

const reference = new Map();
for (const line of readFileSync(cache, 'utf8').split('\n')) {
  const match = /^\s*([0-9a-f]+):\s*\t([^\t]+)(?:\t(.*))?$/.exec(line);
  if (!match) continue;
  // LLVM prints the STF… atomics with two spaces before the address (`stfadd h0,  [x1]`).
  const operands = (match[3] ?? '').replace(/\s*<[^>]*>/g, '').replace(/\s*\/\/.*$/, '').replace(/\s*;.*$/, '').replace(/ {2,}/g, ' ').trim();
  reference.set(parseInt(match[1], 16), operands ? `${match[2]} ${operands}` : match[2]);
}

const view = new DataView(code.buffer, code.byteOffset, code.length);
const vectors = vectorsFile ? new Map((existsSync(vectorsFile) ? JSON.parse(readFileSync(vectorsFile, 'utf8')).vectors : []).map((v) => [v[2].replace(/0x[0-9a-f]+|\b\d+\b|\b([xwvqdshbz])\d+\b/g, '$1N'), v])) : null;
const groups = new Map();
let total = 0;
let mismatched = 0;
let notDecoded = 0;
const missing = new Map();
const started = performance.now();
for (let i = 0; i + 4 <= code.length; i += 4) {
  const pc = text.addr + i;
  const word = view.getUint32(i, true);
  const insn = decode(word, pc);
  const mine = insn.m === '.inst' ? '<unknown>' : formatInsn(insn);
  const theirs = reference.get(pc) ?? '<unknown>';
  total++;
  if (mine === theirs) {
    if (vectors && insn.m !== '.inst') {
      const shape = mine.replace(/0x[0-9a-f]+|\b\d+\b|\b([xwvqdshbz])\d+\b/g, '$1N');
      if (!vectors.has(shape)) vectors.set(shape, [word.toString(16).padStart(8, '0'), pc.toString(16), mine]);
    }
    continue;
  }
  if (insn.m === '.inst' && random) {
    notDecoded++;
    const key = theirs.split(' ')[0];
    missing.set(key, (missing.get(key) ?? 0) + 1);
    continue;
  }
  // Encodings LLVM rejects are grouped by what we made of them.
  const key = theirs === '<unknown>' ? `<unknown> (ours: ${insn.m})` : theirs.split(' ')[0];
  if (only && key !== only && insn.m !== only) continue;
  mismatched++;
  const group = groups.get(key) ?? { count: 0, examples: [] };
  group.count++;
  if (group.examples.length < show) group.examples.push(`${word.toString(16).padStart(8, '0')}  llvm: ${theirs}\n            ours: ${mine}`);
  groups.set(key, group);
}
const seconds = ((performance.now() - started) / 1000).toFixed(1);
for (const [key, group] of [...groups].sort((a, b) => b[1].count - a[1].count)) {
  console.log(`\n${key}: ${group.count}`);
  for (const example of group.examples) console.log(`  ${example}`);
}
if (notDecoded) {
  const top = [...missing].sort((a, b) => b[1] - a[1]).slice(0, 40).map(([k, n]) => `${k} ${n}`).join(', ');
  console.log(`\nnot decoded (LLVM knows them): ${notDecoded.toLocaleString()} — ${top}`);
}
const rate = ((1 - mismatched / total) * 100).toFixed(4);
console.log(`\n${total.toLocaleString()} instructions decoded in ${seconds} s, ${mismatched.toLocaleString()} differ from llvm-objdump (${rate}% match)`);
if (vectors) {
  const list = [...vectors.values()].sort((a, b) => a[2].localeCompare(b[2]));
  writeFileSync(vectorsFile, `${JSON.stringify({ about: 'AArch64 words with the text llvm-objdump prints for them, one per shape of line: [word, pc, text]', vectors: list }, null, 0).replace(/\],\[/g, '],\n[')}\n`);
  console.log(`${vectorsFile}: ${list.length} vectors`);
}
if (mismatched) process.exitCode = 1;
