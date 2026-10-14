/**
 * Checks the x86 decoder against LLVM: the same bytes are decoded here and
 * by llvm-objdump (-M intel), and the two texts are compared instruction by
 * instruction.
 *
 *   node tools/verify-x86.mjs <program>                    the code of a real program (ELF, Mach-O, PE)
 *   node tools/verify-x86.mjs --random 1000000             random encodings, x86-64
 *       --mode 32                                          … i386
 *       --class legacy|0f|0f38|0f3a|vex2|vex3|evex|xop|rex2|3dnow   only that kind
 *       --seed 1
 *   … --show N --only mnemonic
 *   … --vectors tests/fixtures/x86-vectors.json            also keep verified examples
 *
 * llvm-objdump is LLVM_OBJDUMP, or Homebrew's llvm@21 (its version is the
 * one the tables were made from, tools/x86-index.mjs), or the one on the
 * PATH. Each random case is 16 bytes with a symbol of its own, so LLVM starts
 * decoding afresh at each; prefixes, escapes and vector prefixes are chosen
 * to reach every opcode map. Every address LLVM lists is decoded here on its
 * own, so one length decoded differently does not hide what follows; a
 * length that differs is counted apart. LLVM's output is cached in
 * private/verify/.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { elfWrapX86 } from './elf-wrap.mjs';
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
const mode = Number(option('--mode', 64));
const kind = option('--class', null);
const vectorsFile = option('--vectors', null);
const seed = Number(option('--seed', 1));
const file = args[0];

const x86 = await load('core/x86/decode', 'core/x86/print', 'core/macho', 'core/elf', 'core/pe', 'core/image');
await x86.loadX86();

function objdump() {
  for (const candidate of [process.env.LLVM_OBJDUMP, '/opt/homebrew/opt/llvm@21/bin/llvm-objdump', '/usr/local/opt/llvm@21/bin/llvm-objdump']) if (candidate && existsSync(candidate)) return candidate;
  return 'llvm-objdump';
}

/* ------------------------------------------------------------------ *
 * What to decode
 * ------------------------------------------------------------------ */

/** { addr, bytes }[]: runs of code, decoded up to their end. */
let regions;
let cacheName;
let target;
let bits = mode;
/** The slice of a universal file, written out for llvm-objdump. */
let sliceBytes;
if (random) {
  let state = seed >>> 0 || 1;
  const next = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
  const byte = () => next() & 0xff;
  const chance = (p) => next() / 4294967296 < p;
  const CLASSES = ['legacy', '0f', '0f38', '0f3a', 'vex2', 'vex3', 'evex', 'xop', 'rex2', '3dnow'];
  const WEIGHTS = [20, 20, 8, 7, 10, 12, 15, 3, mode === 64 ? 3 : 0, 2];
  const total = WEIGHTS.reduce((a, b) => a + b, 0);
  const pick = () => {
    if (kind) return kind;
    let r = next() % total;
    for (let i = 0; i < CLASSES.length; i++) if ((r -= WEIGHTS[i]) < 0) return CLASSES[i];
    return 'legacy';
  };
  const SIZE = 16;
  const code = new Uint8Array(random * SIZE);
  const symbols = [];
  const base = 0x10000;
  for (let c = 0; c < random; c++) {
    const out = [];
    const legacy = () => {
      if (chance(0.25)) out.push(0x66);
      if (chance(0.15)) out.push(chance(0.5) ? 0xf2 : 0xf3);
      if (chance(0.05)) out.push(0x67);
      if (chance(0.05)) out.push([0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65][next() % 6]);
      if (chance(0.03)) out.push(0xf0);
      if (chance(0.06)) out.splice(next() % (out.length + 1), 0, [0x66, 0xf2, 0xf3, 0x67, 0x2e, 0xf0][next() % 6]);
    };
    const rex = () => {
      if (mode === 64 && chance(0.4)) out.push(0x40 | (next() & 15));
    };
    const cls = pick();
    switch (cls) {
      case 'legacy':
        legacy();
        rex();
        break;
      case '0f':
        legacy();
        rex();
        out.push(0x0f);
        break;
      case '0f38':
        legacy();
        rex();
        out.push(0x0f, 0x38);
        break;
      case '0f3a':
        legacy();
        rex();
        out.push(0x0f, 0x3a);
        break;
      case '3dnow':
        legacy();
        rex();
        out.push(0x0f, 0x0f);
        break;
      case 'vex2':
        if (chance(0.1)) legacy();
        out.push(0xc5, mode === 64 ? byte() : byte() | 0xc0);
        break;
      case 'vex3': {
        if (chance(0.1)) legacy();
        let p0 = byte();
        if (chance(0.9)) p0 = (p0 & 0xe0) | [1, 2, 3, 5, 6, 7][next() % 6];
        if (mode !== 64) p0 |= 0xc0;
        out.push(0xc4, p0, byte());
        break;
      }
      case 'evex': {
        if (chance(0.1)) legacy();
        let p0 = byte();
        if (chance(0.9)) p0 = (p0 & 0xf8) | (1 + (next() % 7));
        if (mode !== 64) p0 |= 0xc0;
        let p1 = byte();
        if (chance(0.85)) p1 |= 4;
        out.push(0x62, p0, p1, byte());
        break;
      }
      case 'xop': {
        let p0 = byte();
        if (chance(0.9)) p0 = (p0 & 0xe0) | (8 + (next() % 3));
        out.push(0x8f, p0, byte());
        break;
      }
      case 'rex2':
        legacy();
        out.push(0xd5, byte());
        break;
    }
    while (out.length < SIZE) out.push(byte());
    code.set(out.slice(0, SIZE), c * SIZE);
    symbols.push(base + c * SIZE);
  }
  regions = [{ addr: base, bytes: code }];
  cacheName = `x86-random-${mode}-${kind ?? 'all'}-${random}-${seed}.txt`;
  target = join(root, 'private', 'verify', cacheName.replace(/\.txt$/, '.o'));
  mkdirSync(join(root, 'private', 'verify'), { recursive: true });
  if (!existsSync(join(root, 'private', 'verify', cacheName))) writeFileSync(target, elfWrapX86(code, base, mode, symbols));
} else if (file) {
  const buffer = new Uint8Array(readFileSync(file));
  regions = codeRegions(buffer);
  const stamp = statSync(file);
  cacheName = `x86-${basename(file)}-${stamp.size}-${Math.floor(stamp.mtimeMs)}.txt`;
  target = file;
} else {
  console.error('usage: node tools/verify-x86.mjs <program> | --random N [--mode 32]');
  process.exit(2);
}

/** The executable sections of a program, through the page's own readers. */
function codeRegions(buffer) {
  let image;
  if (buffer[0] === 0x7f && buffer[1] === 0x45) image = x86.fromElf(x86.parseElf(buffer));
  else if (buffer[0] === 0x4d && buffer[1] === 0x5a) image = x86.fromPe(x86.parsePe(buffer));
  else {
    const macho = x86.parseMachO(buffer, 'x86_64');
    if (macho.sliceOffset || macho.bytes.length !== buffer.length) sliceBytes = macho.bytes;
    image = x86.fromMachO(macho);
  }
  bits = image.arch === 'i386' || image.arch === 'x86' ? 32 : 64;
  return image.sections.filter((s) => s.code && s.offset && s.size).map((s) => ({ addr: s.addr, bytes: image.bytes.subarray(s.offset, s.offset + s.size) }));
}

/* ------------------------------------------------------------------ *
 * LLVM's text
 * ------------------------------------------------------------------ */

const cacheDir = join(root, 'private', 'verify');
mkdirSync(cacheDir, { recursive: true });
const cache = join(cacheDir, cacheName);
if (!existsSync(cache)) {
  console.log(`llvm-objdump on ${regions.reduce((n, r) => n + r.bytes.length, 0).toLocaleString()} bytes…`);
  // A universal file is cut down to its slice first: with --arch, llvm-objdump prints in the style of otool instead.
  if (sliceBytes) {
    target = join(cacheDir, cacheName.replace(/\.txt$/, '.thin'));
    writeFileSync(target, sliceBytes);
  }
  const out = execFileSync(objdump(), ['-d', '-z', '-M', 'intel', '--no-show-raw-insn', target], { encoding: 'utf8', maxBuffer: 2 ** 32, stdio: ['ignore', 'pipe', 'ignore'] });
  writeFileSync(cache, out);
}

/** address → text, in LLVM's order; and where it starts afresh, at a symbol. */
const reference = [];
const symbolStarts = new Set();
for (const line of readFileSync(cache, 'utf8').split('\n')) {
  const symbol = /^([0-9a-f]+) <.*>:$/.exec(line);
  if (symbol) symbolStarts.add(parseInt(symbol[1], 16));
  const match = /^\s*([0-9a-f]+):\s*(.*)$/.exec(line);
  if (!match || !match[2]) continue;
  const text = match[2].replace(/(0x[0-9a-f]+) <[^>]*>/g, '$1').replace(/\s+#.*$/, '').replace(/\s+/g, ' ').trim();
  reference.push([parseInt(match[1], 16), text]);
}

/* ------------------------------------------------------------------ *
 * The comparison
 * ------------------------------------------------------------------ */

// A shape: the mnemonic and its operands with memory as M, numbers as N and registers by class.
const REGISTER_CLASSES = [
  [/\b(?:[abcd][lh]|[sb]pl|[sd]il|r\d+b)\b/g, 'R8'], [/\b(?:[abcd]x|[sd]i|[sb]p|r\d+w)\b/g, 'R16'], [/\b(?:e[abcd]x|e[sd]i|e[sb]p|r\d+d)\b/g, 'R32'],
  [/\b(?:r[abcd]x|r[sd]i|r[sb]p|r\d+)\b/g, 'R64'], [/\b[xyz]mm\d+\b/g, (m) => m.slice(0, 3).toUpperCase()], [/\bk\d\b/g, 'K'], [/\bmm\d\b/g, 'MM'],
  [/\bst\(\d\)/g, 'ST'], [/\btmm\d\b/g, 'TMM'], [/\b[cd]r\d+\b/g, 'CR'],
];
const PREFIX_WORD = /^(?:lock|rep|repne|notrack|addr32|addr16|\{\w+\})$/;
/** The prefixes and the mnemonic of a line. */
const mnemonicOf = (text) => {
  const words = text.split(' ');
  let k = 0;
  while (k < words.length - 1 && PREFIX_WORD.test(words[k])) k++;
  return words.slice(0, k + 1).join(' ');
};
const shapeOf = (text) => REGISTER_CLASSES.reduce((t, [re, to]) => t.replace(re, to), text.replace(/\[[^\]]*\]/g, 'M').replace(/-?0x[0-9a-f]+|\b\d+\b/g, 'N'));
const vectors = vectorsFile ? new Map((existsSync(vectorsFile) ? JSON.parse(readFileSync(vectorsFile, 'utf8')).vectors : []).map((v) => [v[3] === 32 ? `32:${mnemonicOf(v[2])}` : `64:${shapeOf(v[2])}`, v])) : null;
const groups = new Map();
let total = 0;
let mismatched = 0;
let lengths = 0;
const started = performance.now();
const regionOf = (addr) => regions.find((r) => addr >= r.addr && addr < r.addr + r.bytes.length);

for (let k = 0; k < reference.length; k++) {
  const [addr, theirs] = reference[k];
  const region = regionOf(addr);
  if (!region) continue;
  const offset = addr - region.addr;
  const d = x86.decodeX86(region.bytes, offset, region.bytes.length, addr, bits);
  const mine = x86.formatX86(x86.printX86(d));
  total++;
  const hex = [...region.bytes.subarray(offset, offset + Math.max(d.length, 1))].map((b) => b.toString(16).padStart(2, '0')).join(' ');
  const nextAddr = reference[k + 1]?.[0];
  if (mine === theirs) {
    // The next line starts where this one ends, unless a symbol starts there (random cases are 16 bytes each).
    const boundary = symbolStarts.has(nextAddr);
    if (nextAddr !== undefined && nextAddr !== addr + d.length && !boundary && regionOf(nextAddr) === region && nextAddr > addr && nextAddr < addr + 16) {
      lengths++;
      const key = `length of ${theirs.split(' ')[0]}`;
      const group = groups.get(key) ?? { count: 0, examples: [] };
      group.count++;
      if (group.examples.length < show) group.examples.push(`${hex}  llvm: ${nextAddr - addr} bytes, ours: ${d.length}`);
      groups.set(key, group);
    }
    // A vector holds only the instruction's bytes, so it must decode the same without what follows (xacquire looks ahead).
    if (vectors && d.id && x86.formatX86(x86.printX86(x86.decodeX86(region.bytes.slice(offset, offset + d.length), 0, d.length, addr, bits))) === mine) {
      // i386 shares nearly every form with x86-64: one vector per mnemonic is enough there.
      const key = bits === 32 ? `32:${mnemonicOf(mine)}` : `64:${shapeOf(mine)}`;
      if (!vectors.has(key)) vectors.set(key, [hex.replace(/ /g, ''), addr.toString(16), mine, ...(bits === 32 ? [32] : [])]);
    }
    continue;
  }
  const key = theirs === '<unknown>' ? `<unknown> (ours: ${mine.split(' ')[0]})` : mine === '<unknown>' ? `not decoded: ${theirs.split(' ')[0]}` : mnemonicOf(theirs);
  if (only && !key.includes(only)) continue;
  mismatched++;
  const group = groups.get(key) ?? { count: 0, examples: [] };
  group.count++;
  if (group.examples.length < show) group.examples.push(`${hex}\n            llvm: ${theirs}\n            ours: ${mine}`);
  groups.set(key, group);
}

const seconds = ((performance.now() - started) / 1000).toFixed(1);
for (const [key, group] of [...groups].sort((a, b) => b[1].count - a[1].count).slice(0, 80)) {
  console.log(`\n${key}: ${group.count}`);
  for (const example of group.examples) console.log(`  ${example}`);
}
if (groups.size > 80) console.log(`\n… and ${groups.size - 80} more groups`);
const rate = ((1 - mismatched / Math.max(total, 1)) * 100).toFixed(4);
console.log(`\n${total.toLocaleString()} instructions compared in ${seconds} s, ${mismatched.toLocaleString()} differ from llvm-objdump (${rate}% match), ${lengths.toLocaleString()} lengths differ`);
if (vectors) {
  const list = [...vectors.values()].sort((a, b) => a[2].localeCompare(b[2]));
  writeFileSync(vectorsFile, `${JSON.stringify({ about: 'x86 instructions with the text llvm-objdump -M intel prints for them, one per shape of line: [bytes, address, text] for x86-64, [bytes, address, text, 32] for i386', vectors: list }, null, 0).replace(/\],\[/g, '],\n[')}\n`);
  console.log(`${vectorsFile}: ${list.length} vectors`);
}
if (mismatched || lengths) process.exitCode = 1;
