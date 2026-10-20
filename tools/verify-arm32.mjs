/**
 * Checks the AArch32 decoder against LLVM: the same bytes are decoded here
 * and by llvm-objdump (the Android NDK's), and the two texts are compared
 * instruction by instruction.
 *
 *   node tools/verify-arm32.mjs <library.so>                 the code of a real library
 *   node tools/verify-arm32.mjs --random 1000000 --set a32   random encodings
 *       --set a32 | t16 | t32 | thumb (random halfwords, 16- and 32-bit mixed)
 *       --fix ffb00000:f2000000   only words with (word & mask) == value
 *       --seed 1
 *   … --show N --only mnemonic
 *   … --vectors tests/fixtures/arm32-vectors.json   also keep verified examples
 *
 * A real library must keep its symbol table: its mapping symbols ($a, $t,
 * $d) say which bytes are A32, T32 or data, for LLVM and for this tool alike.
 * Data is not compared. LLVM is asked for every extension of AArch32 Armv8.6
 * (crypto, FP16, dot product, BF16, Int8 matrix multiply…), so encodings a
 * v7 library may only reach behind a CPU check are decoded on both sides.
 *
 * Where LLVM names an instruction that we print as .inst, it is counted
 * apart as "not decoded"; where both decode it differently, it is a mismatch,
 * grouped by LLVM's mnemonic, most frequent first. LLVM's output is cached in
 * private/verify/.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';
import { elfWrap32 } from './elf-wrap.mjs';
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
const set = option('--set', 'a32');
const fix = option('--fix', null);
const vectorsFile = option('--vectors', null);
const seed = Number(option('--seed', 1));
const file = args[0];

const MATTR = '+v8.6a,+neon,+crypto,+aes,+sha2,+fullfp16,+fp16fml,+dotprod,+bf16,+i8mm,+crc,+ras,+sb,+mp,+virtualization,+trustzone,+hwdiv,+hwdiv-arm,+clrbhb,+fp-armv8,+d32';

const { decodeArm, decodeThumb, isWide, itAfter, formatInsn, arm32Unconditional } = await load('core/arm32/decode', 'core/arm32/types', 'core/catalog');

/** llvm-objdump from the Android NDK (ANDROID_NDK, or the newest in the SDK), else the one on the PATH. */
function objdump() {
  const ndks = [process.env.ANDROID_NDK, ...(() => {
    const dir = join(homedir(), 'Library', 'Android', 'sdk', 'ndk');
    return existsSync(dir) ? readdirSync(dir).sort((a, b) => a.localeCompare(b, 'en', { numeric: true })).reverse().map((v) => join(dir, v)) : [];
  })()].filter(Boolean);
  for (const ndk of ndks) {
    const prebuilt = join(ndk, 'toolchains', 'llvm', 'prebuilt');
    if (!existsSync(prebuilt)) continue;
    for (const host of readdirSync(prebuilt)) {
      const tool = join(prebuilt, host, 'bin', 'llvm-objdump');
      if (existsSync(tool)) return tool;
    }
  }
  return 'llvm-objdump';
}

/* ------------------------------------------------------------------ *
 * What to decode: regions of A32 or T32 code
 * ------------------------------------------------------------------ */

/** { addr, bytes, thumb }[] and a name for the cache. */
let regions;
let cacheName;
let elfPath;
if (random) {
  // xorshift32: the same seed gives the same words, so LLVM's output can be cached.
  let state = seed >>> 0 || 1;
  const next = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
  const [mask, value] = fix ? fix.split(':').map((v) => parseInt(v, 16) >>> 0) : [0, 0];
  const pick = () => ((next() & ~mask) | (value & mask)) >>> 0;
  const out = [];
  if (set === 'a32') {
    for (let i = 0; i < random; i++) out.push(pick());
    const words = Uint32Array.from(out);
    regions = [{ addr: 0x10000, bytes: new Uint8Array(words.buffer), thumb: false }];
  } else {
    const halves = [];
    for (let i = 0; i < random; i++) {
      if (set === 't16') {
        let hw;
        do hw = next() & 0xffff;
        while (isWide(hw) || (fix && (hw & mask) !== (value & mask)));
        halves.push(hw);
      } else if (set === 't32') {
        let word;
        do word = pick();
        while (!isWide(word >>> 16));
        halves.push(word >>> 16, word & 0xffff);
      } else {
        halves.push(next() & 0xffff);
      }
    }
    if (isWide(halves[halves.length - 1])) halves.push(0xbf00);
    const words = Uint16Array.from(halves);
    regions = [{ addr: 0x10000, bytes: new Uint8Array(words.buffer), thumb: true }];
  }
  cacheName = `arm32-random-${set}-${random}-${seed}${fix ? `-${fix.replace(':', '-')}` : ''}.txt`;
} else if (file) {
  regions = mappedRegions(readFileSync(file));
  const stamp = statSync(file);
  cacheName = `arm32-${basename(file)}-${stamp.size}-${Math.floor(stamp.mtimeMs)}.txt`;
  elfPath = file;
} else {
  console.error('usage: node tools/verify-arm32.mjs <library.so> | --random N --set a32|t16|t32|thumb');
  process.exit(2);
}

/** The executable sections of an ELF file cut where its mapping symbols switch between A32, T32 and data. */
function mappedRegions(buffer) {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  if (buffer.readUInt32BE(0) !== 0x7f454c46 || buffer[4] !== 1) throw new Error('not a 32-bit ELF file');
  const shoff = view.getUint32(32, true);
  const shnum = view.getUint16(48, true);
  const sections = [];
  for (let i = 0; i < shnum; i++) {
    const at = shoff + i * 40;
    sections.push({ type: view.getUint32(at + 4, true), flags: view.getUint32(at + 8, true), addr: view.getUint32(at + 12, true), offset: view.getUint32(at + 16, true), size: view.getUint32(at + 20, true), link: view.getUint32(at + 24, true), index: i });
  }
  const symtab = sections.find((s) => s.type === 2);
  if (!symtab) throw new Error('the library has no symbol table (.symtab): build it without stripping');
  const strtab = sections[symtab.link];
  const marks = [];
  for (let at = symtab.offset; at < symtab.offset + symtab.size; at += 16) {
    const name = view.getUint32(at, true);
    const value = view.getUint32(at + 4, true);
    const shndx = view.getUint16(at + 14, true);
    let end = strtab.offset + name;
    while (buffer[end]) end++;
    const text = buffer.toString('latin1', strtab.offset + name, end);
    const kind = /^\$([atd])(?:\.|$)/.exec(text)?.[1];
    if (kind) marks.push({ addr: value, kind, shndx });
  }
  const out = [];
  for (const section of sections) {
    if (!(section.flags & 4) || section.type !== 1) continue;
    const own = marks.filter((m) => m.shndx === section.index).sort((a, b) => a.addr - b.addr);
    for (let k = 0; k < own.length; k++) {
      const start = own[k].addr;
      const end = k + 1 < own.length ? own[k + 1].addr : section.addr + section.size;
      if (own[k].kind === 'd' || end <= start) continue;
      const bytes = new Uint8Array(buffer.buffer, buffer.byteOffset + section.offset + (start - section.addr), end - start);
      out.push({ addr: start, bytes, thumb: own[k].kind === 't' });
    }
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * LLVM's text
 * ------------------------------------------------------------------ */

const cacheDir = join(root, 'private', 'verify');
mkdirSync(cacheDir, { recursive: true });
const cache = join(cacheDir, cacheName);
if (!existsSync(cache)) {
  let target = elfPath;
  if (!target) {
    target = join(cacheDir, cacheName.replace(/\.txt$/, '.o'));
    writeFileSync(target, elfWrap32(regions[0].bytes, regions[0].addr, regions[0].thumb));
  }
  const triple = regions[0]?.thumb ? 'thumbv8.6a' : 'armv8.6a';
  console.log(`llvm-objdump on ${regions.reduce((n, r) => n + r.bytes.length, 0).toLocaleString()} bytes…`);
  const out = execFileSync(objdump(), ['-d', '-z', `--triple=${triple}`, `--mattr=${MATTR}`, '--no-show-raw-insn', target], { encoding: 'utf8', maxBuffer: 1 << 30, stdio: ['ignore', 'pipe', 'ignore'] });
  writeFileSync(cache, out);
}

const reference = new Map();
for (const line of readFileSync(cache, 'utf8').split('\n')) {
  const match = /^\s*([0-9a-f]+):\s*\t([^\t]+)(?:\t(.*))?$/.exec(line);
  if (!match) continue;
  const operands = (match[3] ?? '').replace(/\s*<[^>]*>/g, '').replace(/\s*@.*$/, '').trim();
  reference.set(parseInt(match[1], 16), operands ? `${match[2]} ${operands}` : match[2].trim());
}

/* ------------------------------------------------------------------ *
 * The comparison
 * ------------------------------------------------------------------ */

// A shape: the mnemonic without its condition, registers and numbers blanked out.
const shapeOf = (text) => {
  const [m, ...rest] = text.split(' ');
  return `${arm32Unconditional(m)} ${rest.join(' ').replace(/-?0x[0-9a-f]+|-?\b\d+(?:\.\d+)?(?:e[+-]\d+)?\b|\b(?:[rsdqcp]\d+|sp|lr|pc)\b/g, 'N')}`;
};
const vectors = vectorsFile ? new Map((existsSync(vectorsFile) ? JSON.parse(readFileSync(vectorsFile, 'utf8')).vectors : []).map((v) => [`${v[0].length > 4 ? (v[3] ? 'T' : 'A') : 't'}:${shapeOf(v[2])}`, v])) : null;
const groups = new Map();
const missing = new Map();
let total = 0;
let mismatched = 0;
let notDecoded = 0;
let lostSync = 0;
const started = performance.now();

for (const region of regions) {
  const view = new DataView(region.bytes.buffer, region.bytes.byteOffset, region.bytes.byteLength);
  let it = [];
  for (let off = 0; off + (region.thumb ? 2 : 4) <= region.bytes.length; ) {
    const pc = region.addr + off;
    let insn;
    let word;
    let shown;
    let inBlock = false;
    if (region.thumb) {
      const hw1 = view.getUint16(off, true);
      const wide = isWide(hw1);
      if (wide && off + 4 > region.bytes.length) break;
      const hw2 = wide ? view.getUint16(off + 2, true) : 0;
      const cond = it[0] ?? -1;
      inBlock = it.length > 0;
      insn = decodeThumb(hw1, hw2, pc, cond);
      word = wide ? ((hw1 << 16) | hw2) >>> 0 : hw1;
      shown = wide ? `${hw1.toString(16).padStart(4, '0')} ${hw2.toString(16).padStart(4, '0')}` : hw1.toString(16).padStart(4, '0');
      // Like LLVM, an instruction it cannot decode, or one of the Armv8 FP/SIMD additions, leaves the IT slot to the next.
      it = itAfter(it, insn, word);
    } else {
      word = view.getUint32(off, true);
      insn = decodeArm(word, pc);
      shown = word.toString(16).padStart(8, '0');
    }
    off += insn.size;
    const theirs = reference.get(pc);
    if (theirs === undefined) {
      lostSync++;
      continue;
    }
    const unknown = insn.m.startsWith('.inst');
    const mine = unknown ? '<unknown>' : formatInsn(insn);
    total++;
    if (mine === theirs) {
      // A vector is decoded on its own, so an instruction inside an IT block is not one.
      if (vectors && !unknown && !inBlock) {
        const key = `${region.thumb ? (insn.size === 4 ? 'T' : 't') : 'A'}:${shapeOf(mine)}`;
        if (!vectors.has(key)) vectors.set(key, [word.toString(16).padStart(insn.size * 2, '0'), pc.toString(16), mine, ...(region.thumb && insn.size === 4 ? [1] : [])]);
      }
      continue;
    }
    if (unknown) {
      notDecoded++;
      const key = theirs.split(' ')[0];
      missing.set(key, (missing.get(key) ?? 0) + 1);
      if (!random && (!only || key === only)) {
        const group = groups.get(`not decoded: ${key}`) ?? { count: 0, examples: [] };
        group.count++;
        if (group.examples.length < show) group.examples.push(`${shown}  llvm: ${theirs}`);
        groups.set(`not decoded: ${key}`, group);
      }
      continue;
    }
    const key = theirs === '<unknown>' ? `<unknown> (ours: ${insn.m})` : theirs.split(' ')[0];
    if (only && key !== only && !insn.m.startsWith(only)) continue;
    mismatched++;
    const group = groups.get(key) ?? { count: 0, examples: [] };
    group.count++;
    if (group.examples.length < show) group.examples.push(`${shown}  llvm: ${theirs}\n            ours: ${mine}`);
    groups.set(key, group);
  }
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
if (lostSync) console.log(`\n${lostSync.toLocaleString()} instructions start where LLVM's do not (a different length was decoded before them)`);
const rate = ((1 - mismatched / Math.max(total, 1)) * 100).toFixed(4);
console.log(`\n${total.toLocaleString()} instructions compared in ${seconds} s, ${mismatched.toLocaleString()} differ from llvm-objdump (${rate}% match), ${notDecoded.toLocaleString()} not decoded`);
if (vectors) {
  const list = [...vectors.values()].sort((a, b) => a[2].localeCompare(b[2]));
  writeFileSync(vectorsFile, `${JSON.stringify({ about: 'AArch32 instructions with the text llvm-objdump prints for them, one per shape of line: [encoding, pc, text] for A32 and 16-bit T32, [hw1hw2, pc, text, 1] for 32-bit T32', vectors: list }, null, 0).replace(/\],\[/g, '],\n[')}\n`);
  console.log(`${vectorsFile}: ${list.length} vectors`);
}
if (mismatched) process.exitCode = 1;
