/**
 * What the page reads of a WebAssembly module, from the core, against the TypeScript reader it
 * replaced (the original project, checked out beside this one, or ORIGINAL): the module itself
 * (every section, type, import, export, segment, name and custom section), every instruction of
 * every function as a row shows it (mnemonic, immediates, opcode, operand text), the source lines
 * of its DWARF, and what each function's card counts (calls, calls through a table, string
 * constants). Damaged modules too: `--damage N` reads N cut and flipped copies of each file, which
 * must fail or warn the same way.
 *
 * One difference is known and counted apart: an f32 constant whose decimal comment the core writes
 * in its shortest digits, as wasm-tools does, where the TypeScript wrote one more (2^90, 2^87, 2^-96;
 * see decimal_float in crates/core/src/wasm/reader.rs) — the same float either way.
 *
 *   node tools/diff-wasm-module.mjs <module.wasm …> [--damage N]
 */
import { readFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { load, root } from './load.mjs';

const args = process.argv.slice(2);
const damageAt = args.indexOf('--damage');
const damage = damageAt < 0 ? 0 : Number(args.splice(damageAt, 2)[1]);
const original = resolve(process.env.ORIGINAL ?? join(root, '..', 'html-disasm'));
const { load: loadOriginal } = await import(join(original, 'tools', 'load.mjs'));
const OLD = await loadOriginal('core/wasm/module', 'core/wasm/decode', 'core/wasm/dwarf', 'core/wasm/opcodes');
const NEW = await load('core/wasm/module', 'core/wasm/decode', 'core/wasm/program');
await NEW.loadEngine();

/** A value as comparable text: Maps as their entries, BigInts marked, keys in order, the bytes left out. */
const canon = (v) =>
  JSON.stringify(v, (key, value) => {
    if (key === 'bytes') return undefined;
    if (typeof value === 'bigint') return `${value}n`;
    if (value instanceof Map) return [...value.entries()];
    if (ArrayBuffer.isView(value)) return [...value];
    if (value && typeof value === 'object' && !Array.isArray(value)) return Object.fromEntries(Object.keys(value).sort().map((k) => [k, value[k]]));
    return value;
  });

/** How a read went: the module, or the error's kind and message. */
function read(M, bytes) {
  try {
    return { module: M.parseWasm(bytes) };
  } catch (err) {
    return { error: `${err.constructor.name}: ${err.message}` };
  }
}

/** The text with the decimal comment of an f32 constant read as the f32 it names. */
const asF32 = (text) => text.replace(/\(;=([^;]*);\)/g, (_, n) => `(;=${Math.fround(Number(n))};)`);
let known = 0;
let files = 0;
let failed = 0;
const notes = [];
function compare(name, bytes, deep) {
  files++;
  const o = read(OLD, bytes);
  const n = read(NEW, bytes);
  const diffs = [];
  if (o.error || n.error) {
    // The original's damaged-module errors were WasmError; ours too (by the same message).
    const norm = (e) => e?.replace(/^(\w*Error|NotWasm): /, '');
    if (norm(o.error) !== norm(n.error) || !o.error !== !n.error) diffs.push(`read: ${o.error ?? 'ok'} / ${n.error ?? 'ok'}`);
  } else {
    if (canon(o.module) !== canon(n.module)) {
      for (const key of Object.keys({ ...o.module, ...n.module })) if (canon(o.module[key]) !== canon(n.module[key])) diffs.push(`module.${key}`);
    }
  }
  return { diffs, o, n };
}

async function deep(name, bytes) {
  const { diffs, o, n } = compare(name, bytes);
  if (!o.error && !n.error && !diffs.length) {
    const t0 = performance.now();
    const p = await NEW.analyzeWasm(n.module);
    // Every instruction as a row reads it.
    let rows = 0;
    let bad = 0;
    let firstBad;
    const ctx = OLD.formatContext(o.module);
    for (let f = 0; f < p.functions.length; f++) {
      const fn = p.functions[f];
      const body = p.bodies[f];
      for (let i = fn.first; i < fn.first + fn.count; i++) {
        // A fresh instruction each time, as the core decodes into: nothing left over from the one before.
        const insn = OLD.decodeAt(o.module.bytes, p.offsets[i], body.end, new OLD.WasmInsn());
        const ours = p.insn(i);
        const op = insn.op ? { code: insn.op.code, imm: insn.op.imm, flags: insn.op.flags, group: insn.op.group, size: insn.op.size } : undefined;
        const theirs = {
          op, m: insn.m, pos: insn.pos, len: insn.len, a: insn.a, b: insn.b, value: insn.value, align: insn.align, mem: insn.mem,
          labels: insn.op?.imm === OLD.IMM.BR_TABLE ? insn.labels : null, ops: OLD.operandsText(insn), opsCtx: OLD.operandsText(insn, ctx),
        };
        rows++;
        if (canon(theirs) !== canon(ours) && insn.m === 'f32.const' && asF32(canon(theirs)) === asF32(canon(ours))) known++;
        else if (canon(theirs) !== canon(ours)) {
          bad++;
          firstBad ??= `${i}: ${canon(theirs)}\n      core: ${canon(ours)}`;
        }
      }
      // The function card: calls, calls through a table or a reference, strings.
      const calls = new Map();
      const strings = new Map();
      let indirect = 0;
      const insn = new OLD.WasmInsn();
      for (let i = fn.first; i < fn.first + Math.min(fn.count, 50000); i++) {
        OLD.decodeAt(o.module.bytes, p.offsets[i], body.end, insn);
        if (insn.m === 'call' || insn.m === 'return_call') calls.set(insn.a, (calls.get(insn.a) ?? 0) + 1);
        else if (insn.op && insn.op.flags & OLD.W.CALL) indirect++;
        else if (insn.m === 'i32.const' && typeof insn.value === 'number' && p.dataRefs.has(insn.value)) {
          const data = p.dataAt(insn.value);
          if (data?.kind === 'string') strings.set(insn.value, data.text);
        }
      }
      const refs = p.functionRefs(f);
      const ourStrings = new Map();
      for (const value of refs.consts) {
        const data = p.dataAt(value);
        if (data?.kind === 'string') ourStrings.set(value, data.text);
      }
      if (canon([[...calls], indirect, [...strings]]) !== canon([refs.calls, refs.indirect, [...ourStrings]])) {
        diffs.push(`function card ${f}`);
        break;
      }
    }
    if (bad) diffs.push(`rows (${bad} of ${rows} differ)\n      TS:   ${firstBad}`);
    // The source lines.
    let theirLines = null;
    try {
      theirLines = OLD.readLines(o.module);
    } catch {
      theirLines = null;
    }
    const ourLines = p.lines;
    if (canon(theirLines && { files: theirLines.files, addrs: theirLines.addrs, rows: theirLines.rows }) !== canon(ourLines && { files: ourLines.files, addrs: ourLines.addrs, rows: ourLines.rows })) diffs.push('lines');
    p.dispose();
    notes.push(`${name.padEnd(40)} ${String(rows).padStart(9)} rows  ${(performance.now() - t0).toFixed(0).padStart(6)} ms  ${diffs.length ? `DIFFERS: ${diffs.join(', ')}` : 'same'}`);
  } else {
    notes.push(`${name.padEnd(40)} ${diffs.length ? `DIFFERS: ${diffs.join(', ')}` : `same (${o.error ? 'not read' : 'read'})`}`);
  }
  if (diffs.length) failed++;
  console.log(notes.at(-1));
}

let seed = 0x9e3779b9;
const random = () => {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return (seed >>>= 0);
};

for (const file of args) {
  const bytes = new Uint8Array(readFileSync(file));
  await deep(basename(file), bytes);
  for (let k = 0; k < damage; k++) {
    const copy = bytes.slice(0, random() % 2 ? bytes.length : 8 + (random() % Math.max(1, bytes.length - 8)));
    for (let f = random() % 4; f > 0 && copy.length > 8; f--) copy[8 + (random() % (copy.length - 8))] ^= 1 << random() % 8;
    const { diffs } = compare(`${basename(file)} damaged #${k}`, copy);
    if (diffs.length) {
      failed++;
      console.log(`${basename(file)} damaged #${k}: DIFFERS: ${diffs.join(', ')}`);
    }
  }
}
console.log(`${files} readings, ${failed} differ${known ? `, ${known} f32 constants in shorter digits` : ''}`);
process.exit(failed ? 1 : 0);
