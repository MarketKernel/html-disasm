/**
 * The containers as the core reads them against the TypeScript reader of the
 * original project (beside this one, or ORIGINAL): every field of the reading
 * must be the same — of an ELF file, a PE file, a Mach-O file (each slice of a universal one). Errors
 * must be the same too.
 *
 *   node tools/diff-containers.mjs <file …>
 */
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { load, root } from './load.mjs';

const original = resolve(process.env.ORIGINAL ?? join(root, '..', 'html-disasm'));
const { load: loadOriginal } = await import(join(original, 'tools', 'load.mjs'));
const modules = ['core/macho', 'core/elf', 'core/pe'];
const NEW = await load(...modules);
const OLD = await loadOriginal(...modules);

/** JSON with object keys sorted, Maps as entry lists, byte arrays as their place and length. */
function canonical(value) {
  return JSON.stringify(value, (key, v) => {
    if (v instanceof Map) return { map: [...v.entries()] };
    if (v instanceof Uint8Array) return { bytes: [v.byteOffset, v.length] };
    if (v && typeof v === 'object' && !Array.isArray(v)) return Object.fromEntries(Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => [k, v[k]]));
    return v;
  });
}

const attempt = (run) => {
  try {
    return run();
  } catch (err) {
    return { error: `${err.constructor.name}: ${err.message}` };
  }
};

function report(file, slice, o, n) {
  const a = canonical(o);
  const b = canonical(n);
  files++;
  if (a !== b) {
    failed++;
    let k = 0;
    while (k < a.length && a[k] === b[k]) k++;
    console.log(`${file}${slice ? ` [${slice}]` : ''}: DIFFERS at ${k}\n  TS:   …${a.slice(Math.max(0, k - 80), k + 120)}\n  core: …${b.slice(Math.max(0, k - 80), k + 120)}`);
  }
}

let files = 0;
let failed = 0;
let oldMs = 0;
let newMs = 0;
for (const file of process.argv.slice(2)) {
  let bytes;
  try {
    bytes = new Uint8Array(readFileSync(file));
  } catch {
    continue;
  }
  if (OLD.isElf(bytes) || OLD.isPe(bytes)) {
    const parse = OLD.isElf(bytes) ? 'parseElf' : 'parsePe';
    let t = performance.now();
    const o = attempt(() => OLD[parse](bytes));
    oldMs += performance.now() - t;
    t = performance.now();
    const n = attempt(() => NEW[parse](bytes));
    newMs += performance.now() - t;
    report(file, undefined, o, n);
    continue;
  }
  const first = attempt(() => OLD.parseMachO(bytes));
  const slices = first.arches && first.arches.length > 1 ? first.arches.map((a) => a.name) : [undefined];
  for (const slice of slices) {
    let t = performance.now();
    const o = attempt(() => OLD.parseMachO(bytes, slice));
    oldMs += performance.now() - t;
    t = performance.now();
    const n = attempt(() => NEW.parseMachO(bytes, slice));
    newMs += performance.now() - t;
    report(file, slice, o, n);
  }
}
console.log(`${files} readings, ${failed} differ (TS ${oldMs.toFixed(0)} ms, core ${newMs.toFixed(0)} ms)`);
if (failed) process.exit(1);
