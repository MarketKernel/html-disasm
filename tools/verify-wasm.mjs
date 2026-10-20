/**
 * Checks the WebAssembly decoder against wasm-tools: every instruction of
 * every function body is decoded here and printed by `wasm-tools print -p`
 * (which marks each line with its offset), and the two texts are compared.
 *
 *   node tools/verify-wasm.mjs [module.wasm …] [--show N] [--only mnemonic]
 *   node tools/verify-wasm.mjs --random 200 [--seed 1]
 *   … --vectors tests/fixtures/wasm-vectors.json   also keep verified examples
 *
 * Custom sections are stripped first (`wasm-tools strip -a`), so the
 * reference names everything by index, as the decoder does; the stripped
 * module is what both read. wasm-tools' output is cached in private/verify/.
 * Mismatches are grouped by the reference's mnemonic, most frequent first.
 *
 * --random makes modules with `wasm-tools smith` from seeded random bytes,
 * every proposal turned on (SIMD, relaxed SIMD, threads, GC, exceptions, tail
 * calls, memory64, multiple memories, wide arithmetic), half of them with
 * bodies of random bytes that need not validate.
 *
 * --vectors adds one example per shape of line to a JSON file that
 * tests/wasm.mjs checks without wasm-tools.
 *
 * Needs wasm-tools (`brew install wasm-tools` or `cargo install wasm-tools`).
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
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
const seed = Number(option('--seed', 1));
const vectorsFile = option('--vectors', null);
const files = args.length ? args : random ? [] : [join(root, 'tests', 'fixtures', 'hello.wasm')];

const { engine, loadEngine } = await load('core/wasm/module');
await loadEngine();

const cacheDir = join(root, 'private', 'verify', 'wasm');
mkdirSync(cacheDir, { recursive: true });
const tool = (...argv) => execFileSync('wasm-tools', argv, { encoding: 'utf8', maxBuffer: 1 << 30, stdio: ['pipe', 'pipe', 'pipe'] });

/** The stripped module and wasm-tools' text of it, cached by the content's hash. */
function reference(bytes, name) {
  const hash = createHash('sha1').update(bytes).digest('hex').slice(0, 16);
  const original = join(cacheDir, `${hash}.wasm`);
  const stripped = join(cacheDir, `${hash}.stripped.wasm`);
  const text = join(cacheDir, `${hash}.txt`);
  if (!existsSync(text)) {
    writeFileSync(original, bytes);
    tool('strip', '-a', original, '-o', stripped);
    writeFileSync(text, tool('print', '-p', stripped));
  }
  return { bytes: new Uint8Array(readFileSync(stripped)), text: readFileSync(text, 'utf8'), name };
}

/** Offset → instruction text, for the lines inside function bodies. */
function referenceLines(text) {
  const lines = new Map();
  let inFunc = false;
  for (const line of text.split('\n')) {
    const match = /^\(;@([0-9a-f]+)\s*;\)(\s*)(.*)$/.exec(line);
    if (!match) continue;
    const offset = parseInt(match[1], 16);
    let body = match[3];
    if (/^\(func\b/.test(body)) {
      inFunc = true;
      continue;
    }
    if (!inFunc) continue;
    if (body.startsWith('(local')) continue;
    if (body === ')') {
      lines.set(offset, 'end');
      inFunc = false;
      continue;
    }
    if (body.startsWith('(')) {
      inFunc = false;
      continue;
    }
    body = body.replace(/\s*;;.*$/, '').replace(/\s*\(;@\d+;\)/g, '').replace(/\s*\(; INVALID ;\)/g, '').trim();
    lines.set(offset, body);
  }
  return lines;
}

function* randomModules(count) {
  let state = seed >>> 0 || 1;
  const next = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
  const features = [
    '--simd-enabled', 'true', '--relaxed-simd-enabled', 'true', '--threads-enabled', 'true', '--gc-enabled', 'true',
    '--exceptions-enabled', 'true', '--tail-call-enabled', 'true', '--memory64-enabled', 'true', '--wide-arithmetic-enabled', 'true',
    '--extended-const-enabled', 'true', '--bulk-memory-enabled', 'true', '--reference-types-enabled', 'true', '--multi-value-enabled', 'true',
    '--min-funcs', '4', '--max-memories', '3', '--max-tables', '3', '--max-funcs', '40', '--max-instructions', '400', '--max-types', '30',
  ];
  for (let i = 0; i < count; i++) {
    const input = Buffer.alloc(4 * (5000 + (next() % 10000)));
    for (let j = 0; j < input.length; j += 4) input.writeUInt32LE(next(), j);
    const extra = i % 2 ? ['--allow-invalid-funcs', 'true'] : [];
    if (i % 3 === 0) extra.push('--min-uleb-size', '2');
    try {
      const out = join(cacheDir, `smith-${seed}-${i}.wasm`);
      if (!existsSync(out)) execFileSync('wasm-tools', ['smith', ...features, ...extra, '-o', out], { input, stdio: ['pipe', 'pipe', 'pipe'] });
      yield { bytes: readFileSync(out), name: `random #${i}` };
    } catch {
      // smith gives up on some inputs; the next one will do.
    }
  }
}

const sources = random ? randomModules(random) : files.map((file) => ({ bytes: readFileSync(file), name: basename(file) }));
const vectors = vectorsFile ? new Map((existsSync(vectorsFile) ? JSON.parse(readFileSync(vectorsFile, 'utf8')).vectors : []).map((v) => [shapeOf(v[1]), v])) : null;
function shapeOf(text) {
  return text.replace(/\(;=[^;]*;\)/g, '').replace(/-?0x[0-9a-f.]+(p[+-]\d+)?|-?\b\d+\b/g, 'N').replace(/\s+/g, ' ');
}

const groups = new Map();
let total = 0;
let mismatched = 0;
let modules = 0;
let unreadable = 0;
const started = performance.now();
for (const source of sources) {
  let ref;
  try {
    ref = reference(source.bytes, source.name);
  } catch (err) {
    unreadable++;
    if (!random) console.log(`${source.name}: wasm-tools could not read it (${String(err.message).split('\n')[0]})`);
    continue;
  }
  modules++;
  const theirs = referenceLines(ref.text);
  // The core's decoder over every body (crates/wasm/src/webassembly.rs, wasm_print): pos, length, known, typed block, text.
  const printed = engine().wasmPrint(ref.bytes);
  if (printed.startsWith('error')) {
    unreadable++;
    console.log(`${source.name}: the core could not read it (${printed.slice(6)})`);
    continue;
  }
  const seen = new Set();
  for (const line of printed.split('\n')) {
    if (!line) continue;
    const [posText, lenText, known, typed, ...rest] = line.split('\t');
    const pos = Number(posText);
    const len = Number(lenText);
    const mine = rest.join('\t');
    const m = mine.split(' ')[0];
    const expected = theirs.get(pos) ?? '<none>';
    seen.add(pos);
    total++;
    if (mine === expected) {
      if (vectors && known === '1' && typed !== '1') {
        const shape = shapeOf(mine);
        if (!vectors.has(shape)) vectors.set(shape, [Buffer.from(ref.bytes.subarray(pos, pos + len)).toString('hex'), mine]);
      }
    } else {
      const key = expected === '<none>' ? `<none> (ours: ${m})` : expected.split(' ')[0];
      if (!only || key === only || m === only) {
        mismatched++;
        const group = groups.get(key) ?? { count: 0, examples: [] };
        group.count++;
        if (group.examples.length < show) group.examples.push(`${source.name} @${pos.toString(16)} ${Buffer.from(ref.bytes.subarray(pos, pos + Math.min(len, 24))).toString('hex')}\n      ref:  ${expected}\n      ours: ${mine}`);
        groups.set(key, group);
      }
    }
  }
  // Lines the reference has that we never reached (we stopped early).
  for (const [pos, text] of theirs) {
    if (seen.has(pos)) continue;
    const key = `missed ${text.split(' ')[0]}`;
    mismatched++;
    const group = groups.get(key) ?? { count: 0, examples: [] };
    group.count++;
    if (group.examples.length < show) group.examples.push(`${source.name} @${pos.toString(16)}  ref: ${text}`);
    groups.set(key, group);
  }
}
const seconds = ((performance.now() - started) / 1000).toFixed(1);
for (const [key, group] of [...groups].sort((a, b) => b[1].count - a[1].count)) {
  console.log(`\n${key}: ${group.count}`);
  for (const example of group.examples) console.log(`  ${example}`);
}
console.log(`\n${modules} module(s)${unreadable ? ` (${unreadable} that wasm-tools could not print left out)` : ''}, ${total.toLocaleString()} instructions, ${mismatched.toLocaleString()} differ (${seconds} s)`);
if (vectors) {
  const list = [...vectors.values()].sort((a, b) => a[1].localeCompare(b[1]));
  writeFileSync(vectorsFile, `${JSON.stringify({ about: 'Instructions with the text wasm-tools prints for them, one per shape of line: made by tools/verify-wasm.mjs --vectors, checked by tests/wasm.mjs.', vectors: list }, null, 0).replace(/\],\[/g, '],\n[')}\n`);
  console.log(`${list.length} vectors in ${vectorsFile}`);
}
process.exit(mismatched ? 1 : 0);
