/**
 * Checks the JVM decoder against javap: every instruction of every method of
 * a class file, a JAR (or .jmod, .war, a ZIP of classes) or a directory of
 * classes is printed here and by the JDK's `javap -c -p`, and the two texts
 * are compared, method by method (in the order of the class file) and
 * instruction by instruction (by pc).
 *
 *   node tools/verify-jvm.mjs [file.jar|File.class|directory …] [--show N] [--only mnemonic]
 *   … --reference tests/fixtures/jvm/hello.javap   also write javap's text of the (one) input there
 *
 * javap writes a switch on several lines; they are joined, as the decoder
 * writes them. Runs of spaces count as one: javap pads its columns. javap's
 * output goes to the terminal's encoding, where a lone surrogate becomes `?`,
 * and so it does here. Its output is cached in private/verify/jvm/.
 *
 * javap is the one on the PATH, or set JAVAP to another (it must be JDK 23 or
 * newer, whose javap is built on the ClassFile API and names the wide forms
 * `iload_w`).
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { codeBlocks, normal } from './javap-text.mjs';
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
const referenceOut = option('--reference', null);
const inputs = args.length ? args : [join(root, 'tests', 'fixtures', 'jvm', 'hello.jar')];
const javap = process.env.JAVAP ?? 'javap';

const C = await load('core/zip', 'core/jvm/classfile', 'core/jvm/decode');

const cacheDir = join(root, 'private', 'verify', 'jvm');
mkdirSync(cacheDir, { recursive: true });

/** The classes of an input: [name, bytes]. */
async function classesOf(file) {
  if (statSync(file).isDirectory()) {
    const out = [];
    const walk = (dir) => {
      for (const name of readdirSync(dir).sort()) {
        const path = join(dir, name);
        if (statSync(path).isDirectory()) walk(path);
        else if (name.endsWith('.class')) out.push([path.slice(file.length + 1), new Uint8Array(readFileSync(path))]);
      }
    };
    walk(file);
    return out;
  }
  let bytes = new Uint8Array(readFileSync(file));
  // A .jmod is a ZIP after a four-byte header.
  if (bytes[0] === 0x4a && bytes[1] === 0x4d) bytes = bytes.subarray(4);
  if (C.isZip(bytes)) {
    const out = [];
    for (const entry of C.zipEntries(bytes)) {
      if (!entry.name.endsWith('.class') || entry.name.startsWith('META-INF/versions/')) continue;
      out.push([entry.name, await C.zipRead(bytes, entry)]);
    }
    return out;
  }
  return [[basename(file), bytes]];
}

/** javap's text of the classes, split by class: the lines of each, by its index. */
function reference(classes) {
  const hash = createHash('sha1');
  for (const [name, bytes] of classes) hash.update(name).update(bytes);
  const key = hash.digest('hex').slice(0, 16);
  const text = join(cacheDir, `${key}.javap`);
  if (!existsSync(text)) {
    const dir = join(cacheDir, key);
    const paths = classes.map(([name, bytes], k) => {
      // Each class in a file of its own, numbered, so javap's "Classfile" lines say which it is.
      const path = join(dir, `${k}`, basename(name));
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, bytes);
      return path;
    });
    const chunks = [];
    for (let k = 0; k < paths.length; k += 300) {
      try {
        chunks.push(execFileSync(javap, ['-J-Dstdout.encoding=UTF-8', '-c', '-p', '-sysinfo', ...paths.slice(k, k + 300)], { encoding: 'utf8', maxBuffer: 1 << 30, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, LANG: 'en_US.UTF-8' } }));
      } catch (err) {
        chunks.push(err.stdout ?? '');
      }
    }
    writeFileSync(text, chunks.join(''));
    execFileSync('rm', ['-rf', dir]);
  }
  const byClass = new Map();
  let lines = null;
  for (const line of readFileSync(text, 'utf8').split('\n')) {
    const head = /^Classfile .*\/(\d+)\/[^/]+$/.exec(line);
    if (head) {
      lines = [];
      byClass.set(Number(head[1]), lines);
    } else if (lines) lines.push(line);
  }
  return { byClass, text: readFileSync(text, 'utf8') };
}

const LONE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

let total = 0;
let same = 0;
const mismatches = new Map();
for (const file of inputs) {
  const classes = await classesOf(file);
  if (!classes.length) {
    console.log(`${basename(file)}: no classes, skipped`);
    continue;
  }
  const { byClass, text } = reference(classes);
  if (referenceOut) writeFileSync(referenceOut, text.replace(/^Classfile .*\n(\s+(Last modified|SHA-256|MD5).*\n)*/gm, ''));
  let fileTotal = 0;
  let fileSame = 0;
  let missing = 0;
  const extra = [];
  const insn = new C.JvmInsn();
  for (let k = 0; k < classes.length; k++) {
    const [name, bytes] = classes[k];
    let cf;
    try {
      cf = new C.ClassFile(bytes, name);
    } catch (err) {
      console.log(`  ${name}: ${err.message}`);
      continue;
    }
    const blocks = codeBlocks(byClass.get(k) ?? []);
    const methods = cf.methods.filter((m) => m.code);
    if (blocks.length !== methods.length) missing += Math.abs(blocks.length - methods.length);
    methods.forEach((method, m) => {
      const code = method.code;
      const ours = new Map();
      for (let pos = code.offset; pos < code.offset + code.length; pos += insn.len) {
        C.decodeAt(cf.bytes, code.offset, pos, code.offset + code.length, insn);
        ours.set(insn.at, C.insnText(cf, insn));
      }
      const theirs = new Set((blocks[m] ?? []).map(([pc]) => pc));
      for (const pc of ours.keys()) if (!theirs.has(pc)) extra.push(`${cf.name}.${method.name}${method.descriptor} @${pc}: ${ours.get(pc)}`);
      for (const [pc, want] of blocks[m] ?? []) {
        const mnemonic = want.split(/\s/)[0];
        if (only && mnemonic !== only) continue;
        total++;
        fileTotal++;
        const got = ours.get(pc);
        if (got !== undefined && normal(got.replace(LONE, '?')) === normal(want)) {
          same++;
          fileSame++;
          continue;
        }
        const list = mismatches.get(mnemonic) ?? [];
        list.push({ where: `${cf.name}.${method.name}${method.descriptor} @${pc}`, want: normal(want), got: got === undefined ? undefined : normal(got) });
        mismatches.set(mnemonic, list);
      }
    });
  }
  console.log(`${basename(file)}: ${classes.length} classes, ${fileTotal} instructions in javap, ${fileSame} the same${missing ? `, ${missing} methods not matched` : ''}${extra.length ? `, ${extra.length} decoded here that javap does not print` : ''}`);
  for (const line of extra.slice(0, show)) console.log(`  not in javap: ${line}`);
}

const sorted = [...mismatches].sort((a, b) => b[1].length - a[1].length);
for (const [mnemonic, list] of sorted) {
  console.log(`\n${mnemonic}: ${list.length} different`);
  for (const { where, want, got } of list.slice(0, show)) console.log(`  ${where}\n    javap: ${want}\n    ours:  ${got ?? '(none)'}`);
}
console.log(`\n${same} of ${total} instructions the same${total ? ` (${((same / total) * 100).toFixed(3)}%)` : ''}`);
process.exit(same === total ? 0 : 1);
