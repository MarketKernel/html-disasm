/**
 * The image of a native program the page takes from the core — its sections, symbols, imports,
 * exports, stubs, slots, function starts, entry point, Arm code marks and Objective-C metadata —
 * against the TypeScript that built it (fromMachO, fromElf, fromPe and the Objective-C reader of
 * the original project, checked out beside this one, or ORIGINAL). A Mach-O file is read at the
 * slice the page opens (SLICE=x86_64 for another); a hybrid Windows program in both its views.
 *
 * `--damage N` also reads N copies of each file with a few bytes flipped: both must fail to read
 * it, or build the same image.
 *
 *   node tools/diff-image.mjs <program …> [--damage N]
 */
import { readFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { load, root } from './load.mjs';

const original = resolve(process.env.ORIGINAL ?? join(root, '..', 'html-disasm'));
const { load: loadOriginal } = await import(join(original, 'tools', 'load.mjs'));
const modules = ['core/macho', 'core/elf', 'core/pe', 'core/image'];
const OLD = await loadOriginal(...modules);
const NEW = await load(...modules);
await NEW.loadEngine();
await OLD.loadEngine?.();
const SLICE = process.env.SLICE;

/** An image as comparable text: no bytes, no containers, no functions; Maps and Sets as their entries; keys in order, false and undefined left out. */
const canon = (image) =>
  JSON.stringify(image, (key, value) => {
    if (['bytes', 'macho', 'elf', 'pe', 'source', 'demangle', 'demangleAll'].includes(key)) return undefined;
    if (value instanceof Map) return [...value.entries()];
    if (value instanceof Set) return [...value];
    if (value && typeof value === 'object' && !Array.isArray(value)) return Object.fromEntries(Object.keys(value).sort().filter((k) => value[k] !== undefined && value[k] !== false).map((k) => [k, value[k]]));
    return value;
  });

/** The images a file opens as (one, or a hybrid program's two), or why it does not. */
function images(M, bytes) {
  try {
    if (M.isPe(bytes)) {
      const pe = M.parsePe(bytes);
      if (pe.clr) return { skip: '.NET' };
      return { list: pe.hybrid ? [M.fromPe(pe, 'arm'), M.fromPe(pe, 'x64')] : [M.fromPe(pe)] };
    }
    if (M.isElf(bytes)) return { list: [M.fromElf(M.parseElf(bytes))] };
    return { list: [M.fromMachO(M.parseMachO(bytes, SLICE))] };
  } catch (err) {
    return { error: `${err.constructor.name}: ${err.message}` };
  }
}

const args = process.argv.slice(2);
const damageAt = args.indexOf('--damage');
const damage = damageAt < 0 ? 0 : Number(args.splice(damageAt, 2)[1]);

let seed = 0x9e3779b9;
const random = () => {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return (seed >>>= 0);
};

let files = 0;
let failed = 0;
let threw = 0;
function compare(name, bytes, quiet = false) {
  files++;
  const t0 = performance.now();
  const o = images(OLD, bytes);
  const n = images(NEW, bytes);
  let note;
  if (o.skip || n.skip) note = `skipped (${o.skip ?? n.skip})`;
  else if (o.error || n.error) {
    // The original's readers threw a RangeError reading past a damaged file's end, where the core reads zeros.
    if (o.error && !n.error && /RangeError|out of bounds|outside the bounds/.test(o.error)) {
      threw++;
      note = 'the TypeScript threw';
    } else {
      const norm = (e) => e?.replace(/^\w+: /, '');
      note = norm(o.error) === norm(n.error) ? `not read by either (${o.error})` : `DIFFERS: read: ${o.error ?? 'ok'} / ${n.error ?? 'ok'}`;
    }
  } else {
    const diffs = [];
    o.list.forEach((image, k) => {
      const a = canon(image);
      const b = canon(n.list[k]);
      if (a === b) return;
      for (const key of Object.keys({ ...image, ...n.list[k] })) {
        if (['bytes', 'macho', 'elf', 'pe', 'source', 'demangle', 'demangleAll'].includes(key)) continue;
        const x = canon({ v: image[key] });
        const y = canon({ v: n.list[k][key] });
        if (x === y) continue;
        let at = 0;
        while (at < x.length && x[at] === y[at]) at++;
        diffs.push(`${key}${o.list.length > 1 ? ` (view ${k})` : ''} at ${at}\n      TS:   …${x.slice(Math.max(0, at - 120), at + 200)}\n      core: …${y.slice(Math.max(0, at - 120), at + 200)}`);
      }
    });
    note = diffs.length ? `DIFFERS: ${diffs.join('\n    ')}` : `same (${o.list.map((i) => `${i.sections.length} sections, ${i.symbols.length} symbols`).join('; ')})`;
  }
  if (note.startsWith('DIFFERS')) failed++;
  if (!quiet || note.startsWith('DIFFERS')) console.log(`${name.padEnd(40)} ${(performance.now() - t0).toFixed(0).padStart(6)} ms  ${note}`);
}

for (const file of args) {
  let bytes;
  try {
    bytes = new Uint8Array(readFileSync(file));
  } catch {
    continue;
  }
  compare(basename(file), bytes);
  for (let k = 0; k < damage; k++) {
    const copy = bytes.slice();
    for (let f = 1 + (random() % 4); f > 0; f--) copy[random() % copy.length] ^= 1 << random() % 8;
    compare(`${basename(file)} damaged #${k}`, copy, true);
  }
}
console.log(`${files} readings, ${failed} differ${threw ? `, ${threw} the TypeScript threw on` : ''}`);
process.exit(failed ? 1 : 0);
