/**
 * What the page reads of a ZIP file, from the core, against the TypeScript that read it (the
 * original project, checked out beside this one, or ORIGINAL): the names of its entries, the
 * programs of an app (.ipa, a zipped macOS app) with what their Info.plist and provisioning
 * profile say, the native libraries of an Android package, and the bytes of every one of them.
 *
 * `--damage N` also reads N copies of each file with a few bytes flipped: both must fail the same
 * way, or read the same.
 *
 *   node tools/diff-archive.mjs <file.ipa|app.zip|.apk|.apks|.aab …> [--damage N]
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { load, root } from './load.mjs';

const original = resolve(process.env.ORIGINAL ?? join(root, '..', 'html-disasm'));
const { load: loadOriginal } = await import(join(original, 'tools', 'load.mjs'));
const OLD = await loadOriginal('core/zip', 'core/bundle', 'core/plist');
const NEW = await load('core/archive');

const hash = (bytes) => createHash('sha1').update(bytes).digest('hex');
const canon = (v) =>
  JSON.stringify(v, (key, value) => {
    if (value instanceof Date) return Number.isNaN(value.getTime()) ? 'Invalid Date' : value.toISOString();
    if (value && typeof value === 'object' && !Array.isArray(value)) return Object.fromEntries(Object.keys(value).sort().filter((k) => value[k] !== undefined).map((k) => [k, value[k]]));
    return value;
  });

/**
 * What an error was, as the page shows it: a NotZip's message, or the kind and message of another.
 * Deflated data that does not inflate is a TypeError whose message is the JavaScript engine's own
 * (Node's DecompressionStream gives none, or another): only its kind is compared.
 */
const what = (err) => (err instanceof TypeError ? 'TypeError' : `${err instanceof OLD.NotZip || err instanceof NEW.NotZip ? 'NotZip' : err.constructor.name}: ${err.message}`);

/** The original's reading: names, an app's programs, a package's libraries, and each one's bytes. */
async function theirs(bytes) {
  const out = {};
  try {
    out.names = OLD.zipEntries(bytes).map((e) => e.name);
  } catch (err) {
    out.names = what(err);
  }
  try {
    out.programs = OLD.isAppArchive(OLD.zipEntries(bytes)) ? await OLD.bundledPrograms(bytes) : [];
    out.programs = await Promise.all(out.programs.map(async (p) => ({ ...p, read: await p.read().then(hash, what) })));
  } catch (err) {
    out.programs = what(err);
  }
  try {
    out.libraries = await OLD.packagedLibraries(bytes);
    out.libraries = await Promise.all(out.libraries.map(async (l) => ({ ...l, read: await l.read().then(hash, what) })));
  } catch (err) {
    out.libraries = what(err);
  }
  return out;
}

async function ours(bytes) {
  const archive = new NEW.Archive(bytes);
  const out = {};
  try {
    out.names = archive.names();
  } catch (err) {
    out.names = what(err);
  }
  try {
    out.programs = await Promise.all(archive.programs().map(async (p) => ({ ...p, read: await p.read().then(hash, what) })));
  } catch (err) {
    out.programs = what(err);
  }
  try {
    out.libraries = await Promise.all(archive.libraries().map(async (l) => ({ ...l, read: await l.read().then(hash, what) })));
  } catch (err) {
    out.libraries = what(err);
  }
  archive.dispose();
  return out;
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
async function compare(name, bytes, quiet = false) {
  files++;
  const t0 = performance.now();
  const o = await theirs(bytes);
  const n = await ours(bytes);
  const diffs = [];
  for (const key of ['names', 'programs', 'libraries']) {
    const a = canon(o[key]);
    const b = canon(n[key]);
    if (a === b) continue;
    let at = 0;
    while (at < a.length && a[at] === b[at]) at++;
    diffs.push(`${key} at ${at}\n      TS:   …${a.slice(Math.max(0, at - 150), at + 250)}\n      core: …${b.slice(Math.max(0, at - 150), at + 250)}`);
  }
  if (diffs.length) failed++;
  const summary = `${Array.isArray(n.names) ? n.names.length : 0} entries, ${Array.isArray(n.programs) ? n.programs.length : n.programs} programs, ${Array.isArray(n.libraries) ? n.libraries.length : n.libraries} libraries`;
  if (!quiet || diffs.length) console.log(`${name.padEnd(36)} ${(performance.now() - t0).toFixed(0).padStart(6)} ms  ${diffs.length ? `DIFFERS: ${diffs.join('\n    ')}` : `same (${summary})`}`);
}

for (const file of args) {
  const bytes = new Uint8Array(readFileSync(file));
  await compare(basename(file), bytes);
  for (let k = 0; k < damage; k++) {
    const copy = bytes.slice();
    for (let f = 1 + (random() % 4); f > 0; f--) copy[random() % copy.length] ^= 1 << random() % 8;
    await compare(`${basename(file)} damaged #${k}`, copy, true);
  }
}
console.log(`${files} readings, ${failed} differ`);
process.exit(failed ? 1 : 0);
