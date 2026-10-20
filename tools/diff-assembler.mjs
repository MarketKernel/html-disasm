/**
 * The arm64 assembler of the core (crates/core/src/arm64/encode.rs) against the TypeScript one it
 * replaced (the original project, checked out beside this one, or ORIGINAL): the same word, or the
 * same error in the same words, for every line tried. The lines: every decoder vector, the text of
 * random words, those lines spelt the other ways people type them (decimal, upper case, spaces,
 * comments, llvm-objdump's <symbol>, names for targets, condition aliases), and random mutations of
 * them, each at a few addresses.
 *
 * One difference is known and counted apart: the original looked mnemonics up in plain objects, so
 * `constructor` reached Object's own constructor and assembled to nonsense; the core does not know it.
 *
 *   node tools/diff-assembler.mjs [--random N] [--mutations N] [--seed S]
 */
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { load, root } from './load.mjs';

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const at = args.indexOf(name);
  return at < 0 ? fallback : Number(args[at + 1]);
};
const randomWords = option('--random', 200000);
const mutations = option('--mutations', 4);
let seed = option('--seed', 0x2545f491) >>> 0 || 1;

const original = resolve(process.env.ORIGINAL ?? join(root, '..', 'html-disasm'));
const { load: loadOriginal } = await import(join(original, 'tools', 'load.mjs'));
const OLD = await loadOriginal('core/arm64/encode', 'core/arm64/decode', 'core/arm64/types');
const NEW = await load('core/arm64/encode');

const random = () => {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return (seed >>>= 0);
};
const pick = (list) => list[random() % list.length];

// Names a line may use for a target, resolved the same way for both.
const NAMES = new Map([['main', 0x100004000], ['helper', 0x100008010], ['_start', 0x1000], ['L100004020', 0x100004020], ['core::fmt::write', 0x100200000], ['far', 0x900000000]]);
const resolveName = (name) => NAMES.get(name);

/** Mnemonics the original's tables answered through Object.prototype. */
const inherited = (text) => Object.hasOwn(Object.prototype, text.trim().split(/\s/)[0]?.toLowerCase() ?? '');
let known = 0;
let lines = 0;
let words = 0;
let errors = 0;
const differ = [];
function compare(text, pc) {
  lines++;
  let theirs;
  let ours;
  try {
    theirs = OLD.assemble(text, pc, resolveName);
  } catch (err) {
    // The original throws on a few inputs (an object key for a mnemonic): nothing to compare with.
    return;
  }
  ours = NEW.assemble(text, pc, resolveName);
  if (ours.word !== undefined) words++;
  else errors++;
  const a = theirs.word !== undefined ? `word ${(theirs.word >>> 0).toString(16)}` : `error ${theirs.error}`;
  const b = ours.word !== undefined ? `word ${(ours.word >>> 0).toString(16)}` : `error ${ours.error}`;
  if (a === b) return;
  if (inherited(text)) known++;
  else differ.push({ text, pc, theirs: a, ours: b });
}

const PCS = [0x100004000, 0x1000, 0x100004002, 0x7ffffffff000, 0];

/** The other spellings of a line people type. */
function variants(text) {
  const out = [text, text.toUpperCase(), `  ${text}  `, `${text} // a comment`, `${text} ; another`, text.replace(/, /g, ',')];
  out.push(text.replace(/#0x([0-9a-f]+)/g, (_, h) => `#${BigInt(`0x${h}`)}`));
  out.push(text.replace(/#(-?)0x([0-9a-f]+)/g, (_, s, h) => `#${s}${BigInt(`0x${h}`) + 1n}`));
  out.push(text.replace(/0x([0-9a-f]+)$/, (m) => `${m} <helper>`));
  out.push(text.replace(/0x100004020/g, 'L100004020').replace(/0x100008010/g, 'helper'));
  out.push(text.replace(/\bhs\b/g, 'cs').replace(/\blo\b/g, 'cc'));
  out.push(text.replace(/\bx(\d+)\b/, 'w$1'), text.replace(/\bw(\d+)\b/, 'x$1'));
  out.push(text.replace(/, [^,]*$/, ''), `${text}, #1`);
  return out;
}

const ALPHABET = 'xwsdqhb0123456789#[]!,- abcdefghijklmnopqrstuvwyz.<>+:;{}_';
function mutate(text) {
  const chars = [...text];
  const at = random() % (chars.length + 1);
  switch (random() % 4) {
    case 0:
      chars.splice(at, 1);
      break;
    case 1:
      chars.splice(at, 0, pick([...ALPHABET]));
      break;
    case 2:
      chars[at] = pick([...ALPHABET]);
      break;
    default:
      chars.splice(at, 0, pick(['xzr', 'sp', 'wsp', '#-1', '#0x1000', 'lsl #12', 'uxtw', 'sxtx #3', '[x0]', 'main', 'main+0x10', '#1.5', '#0x10000000000000000000000000000000000']));
  }
  return chars.join('');
}

function tryLine(text) {
  for (const v of variants(text)) {
    const pc = pick(PCS);
    compare(v, pc);
    for (let k = 0; k < mutations; k++) compare(mutate(v), pick(PCS));
  }
}

const started = performance.now();
const { vectors } = JSON.parse(readFileSync(join(root, 'tests', 'fixtures', 'decode-vectors.json'), 'utf8'));
for (const [, , text] of vectors) tryLine(text);
console.log(`vectors: ${lines} lines`);
for (let i = 0; i < randomWords; i++) {
  const word = random();
  const pc = pick(PCS) & ~3;
  tryLine(OLD.formatInsn(OLD.decode(word, pc)));
}
for (const text of ['', '   ', '// only a comment', 'nop', 'ret', 'b main', 'bl helper+8', 'adrp x0, far', 'adr x0, main-4', 'b unknown', 'mov x0, #0x10000000000000000000000000000000000', 'ldr x0, [x1, #0x10000000000000000000000000000000001]', 'b #0x100000000000000000000000000000000', 'fmov d0, #-0.0', 'fcmp s0, #-0.0', 'constructor', '__proto__', 'tostring']) {
  for (const pc of PCS) compare(text, pc);
}

console.log(`${lines} lines in ${((performance.now() - started) / 1000).toFixed(1)} s: ${words} words, ${errors} errors, ${differ.length} different${known ? `, ${known} known (an Object.prototype name)` : ''}`);
for (const d of differ.slice(0, 30)) console.log(`  ${JSON.stringify(d.text)} at 0x${d.pc.toString(16)}\n    TS:   ${d.theirs}\n    core: ${d.ours}`);
process.exit(differ.length ? 1 : 0);
