/**
 * Signing a patched macOS program again, by the core, against the TypeScript that signed it (with
 * Web Crypto; the original project, checked out beside this one, or ORIGINAL): for each file, a
 * byte of its code is changed (as a patch would) and both sign every slice again; the files that
 * come out, what each says the opened slice had, and the errors must be the same.
 *
 * `--damage N` also signs N copies whose signature has a few bytes flipped.
 *
 *   node tools/diff-resign.mjs <program …> [--damage N]
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { load, root } from './load.mjs';

const original = resolve(process.env.ORIGINAL ?? join(root, '..', 'html-disasm'));
const { load: loadOriginal } = await import(join(original, 'tools', 'load.mjs'));
const OLD = await loadOriginal('core/macho', 'core/patch');
const NEW = await load('core/macho', 'core/patch');

const hash = (bytes) => createHash('sha1').update(bytes).digest('hex');

async function sign(M, bytes) {
  const file = bytes.slice();
  let image;
  try {
    image = M.parseMachO(file);
  } catch (err) {
    return { error: `parse: ${err.message}` };
  }
  try {
    const r = await M.resignFile(file, image);
    return { result: JSON.stringify({ was: r.was, team: r.team ?? null, identifier: r.identifier, entitlements: r.entitlements }), file: hash(file) };
  } catch (err) {
    return { error: `${err instanceof OLD.CannotSign || err instanceof NEW.CannotSign ? 'CannotSign' : err.constructor.name}: ${err.message}`, file: hash(file) };
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

/**
 * Whether the TypeScript would not finish: a superblob whose blob count runs far past its table
 * (a flipped high bit) had it loop that many times, keeping a blob each time, until memory ran out.
 */
function endless(bytes, image) {
  const at = image.signatureAt;
  if (!at) return false;
  const p = image.sliceOffset + at.offset + 8;
  const count = ((bytes[p] << 24) | (bytes[p + 1] << 16) | (bytes[p + 2] << 8) | bytes[p + 3]) >>> 0;
  return count > 1 << 20;
}

let files = 0;
let failed = 0;
let signed = 0;
let skipped = 0;
async function compare(name, bytes, quiet = false, image = undefined) {
  files++;
  if (image && endless(bytes, image)) {
    // The core reads such a table to its end; it is signed (or refused) without the TypeScript to compare.
    await sign(NEW, bytes);
    skipped++;
    return;
  }
  const o = await sign(OLD, bytes);
  const n = await sign(NEW, bytes);
  const a = JSON.stringify(o);
  const b = JSON.stringify(n);
  if (o.result) signed++;
  if (a !== b) failed++;
  if (!quiet || a !== b) console.log(`${name.padEnd(40)} ${a === b ? `same (${o.result ? JSON.parse(o.result).was : o.error})` : `DIFFERS\n      TS:   ${a}\n      core: ${b}`}`);
}

for (const file of args) {
  let bytes;
  try {
    bytes = new Uint8Array(readFileSync(file));
  } catch {
    continue;
  }
  let image;
  try {
    image = OLD.parseMachO(bytes);
  } catch {
    continue;
  }
  // A patch: one byte of the code changed.
  const text = image.sections.find((s) => s.sectname === '__text' && s.offset);
  if (text) bytes[image.sliceOffset + text.offset] ^= 0x01;
  await compare(basename(file), bytes);
  const at = image.signatureAt;
  for (let k = 0; k < damage && at; k++) {
    const copy = bytes.slice();
    // Flips in the signature's header and code directory, where the reading decides things.
    for (let f = 1 + (random() % 3); f > 0; f--) copy[image.sliceOffset + at.offset + (random() % Math.min(at.size, 600))] ^= 1 << random() % 8;
    await compare(`${basename(file)} damaged #${k}`, copy, true, image);
  }
}
console.log(`${files} signings, ${signed} signed, ${failed} differ${skipped ? `, ${skipped} the TypeScript would not finish` : ''}`);
process.exit(failed ? 1 : 0);
