/**
 * What the page shows of Java classes, from the core, against the TypeScript that read the
 * classes for it (the original project, checked out beside this one, or ORIGINAL): every
 * instruction as a row and the details show it (its text as javap prints it, the operand, the
 * constant it names and javap's comment for it, the local it reads, its bytes, an invokedynamic's
 * bootstrap method and arguments), every method's card and HLA64 header, every class's card (and
 * a module's), every field's declaration, the owner of every member of another class, what each
 * method's card counts (calls, invokedynamic calls, strings), and every string as javap writes it.
 *
 * `--damage N` also reads N copies of classes of each file with a few bytes flipped, each as a
 * class file of its own: both must fail to read it, or show the same of it.
 *
 *   node tools/diff-jvm-page.mjs <file.jar|File.class|.jmod …> [--damage N]
 */
import { readFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { load, root } from './load.mjs';

const original = resolve(process.env.ORIGINAL ?? join(root, '..', 'html-disasm'));
const { load: loadOriginal } = await import(join(original, 'tools', 'load.mjs'));
const OLD = await loadOriginal('core/zip', 'core/jvm/opcodes', 'core/jvm/classfile', 'core/jvm/decode', 'core/jvm/program', 'core/jvm/hla');
const NEW = await load('core/jvm/program');
await NEW.loadEngine();

/** A value as comparable text: keys in order, undefined as null. */
const canon = (v) =>
  JSON.stringify(v, (key, value) => {
    if (value === undefined) return null;
    if (value && typeof value === 'object' && !Array.isArray(value)) return Object.fromEntries(Object.keys(value).sort().map((k) => [k, value[k] ?? null]));
    return value;
  });

/** The local a slot holds at an instruction, as the original page wrote it. */
function localComment(cf, code, slot, pc, len) {
  const locals = cf.localVariables(code).filter((v) => v.slot === slot);
  const v = locals.find((l) => pc >= l.start && pc < l.start + l.length) ?? locals.find((l) => pc + len >= l.start && pc + len <= l.start + l.length);
  return v ? `${v.name}: ${OLD.fieldType(v.descriptor)}` : '';
}

/** A row as the original page read it. */
function theirInsn(o, i, f) {
  const body = o.bodies[f];
  const cf = o.classes[body.cls];
  const insn = o.insn(i, new OLD.JvmInsn());
  const pool = OLD.poolIndex(insn);
  const tag = cf.tags[pool] ?? 0;
  let local = '';
  if (insn.op?.operand === OLD.OPERAND.NONE) {
    const slot = /^[ilfda](?:load|store)_([0-3])$/.exec(insn.m);
    if (slot) local = localComment(cf, body.code, Number(slot[1]), insn.at, insn.len);
  } else if ([OLD.OPERAND.LOCAL, OLD.OPERAND.LOCAL_W, OLD.OPERAND.IINC, OLD.OPERAND.IINC_W].includes(insn.op?.operand)) local = localComment(cf, body.code, insn.a, insn.at, insn.len);
  let dynamic = null;
  if (insn.op?.operand === OLD.OPERAND.DYNAMIC && pool) {
    const bootstrap = cf.bootstrapMethods()[cf.dynamic(pool).bootstrap];
    dynamic = bootstrap ? { method: OLD.constantComment(cf, bootstrap.method), args: bootstrap.args.map((a) => [a, cf.tags[a] ?? 0, OLD.constantComment(cf, a)]) } : { method: null, args: [] };
  }
  return {
    op: insn.op ? { code: insn.op.code, operand: insn.op.operand, flags: insn.op.flags } : null,
    m: insn.m,
    at: insn.at,
    len: insn.len,
    a: insn.a,
    b: insn.b,
    keys: insn.keys,
    targets: insn.targets,
    operand: OLD.operandText(cf, insn).operand,
    text: OLD.insnText(cf, insn),
    pool,
    tag,
    comment: pool ? OLD.constantComment(cf, pool) : '',
    string: pool && tag === OLD.CONSTANT.String ? cf.utf8(cf.ref1(pool)) : null,
    local,
    bytes5: OLD.bytesText(cf.bytes, o.fileOffset(i), insn.len, 5),
    bytes24: OLD.bytesText(cf.bytes, o.fileOffset(i), insn.len, 24),
    dynamic,
  };
}

/** A method's card and header as the original page made them. */
function theirMethod(o, f) {
  const body = o.bodies[f];
  const cf = o.classes[body.cls];
  const method = body.method;
  const lines = cf.lineNumbers(body.code);
  const catchText = (h) => (h.catchType ? OLD.javaName(cf.className(h.catchType)) : 'any');
  return {
    access: method.access,
    modifiers: OLD.modifiers(method.access, 'method'),
    descriptor: method.descriptor,
    signature: cf.signature(method.attributes) ?? null,
    exceptions: cf.exceptions(method).map(OLD.javaName),
    class: OLD.javaName(cf.name),
    path: cf.path,
    source: cf.sourceFile() ?? null,
    firstLine: lines.length ? Math.min(...lines.map(([, line]) => line)) : null,
    codeLength: body.code.length,
    maxStack: body.code.maxStack,
    maxLocals: body.code.maxLocals,
    locals: cf.localVariables(body.code).map((v) => [v.slot, v.name, OLD.fieldType(v.descriptor), v.start, v.length]),
    handlers: body.code.handlers.map((h) => ({ start: h.start, end: h.end, handler: h.handler, catch: catchText(h) })),
    params: OLD.headerParams(o, f).map(({ name, type }) => [name, type]),
    ret: OLD.methodTypes(method.descriptor).ret.replace(/(?:[\w$]+\.)+/g, ''),
  };
}

/** A class's card as the original page made it. */
function theirClass(o, k) {
  const cf = o.classes[k];
  let module;
  try {
    module = cf.access & 0x8000 ? (cf.module() ?? null) : null;
  } catch (err) {
    module = `throws ${err.message}`;
  }
  return {
    java: OLD.javaName(cf.name),
    modifiers: OLD.modifiers(cf.access, 'class'),
    kind: OLD.classKind(cf),
    extends: cf.superClass ? OLD.javaName(cf.className(cf.superClass)) : null,
    implements: cf.interfaces.map((i) => OLD.javaName(cf.className(i))),
    source: cf.sourceFile() ?? null,
    pool: cf.tags.length - 1,
    attributes: cf.attributes.map((a) => a.name),
    module,
  };
}

/** What a method's card counts, as the original page did. */
function theirRefs(o, f) {
  const fn = o.functions[f];
  const body = o.bodies[f];
  const cf = o.classes[body.cls];
  const calls = new Map();
  const strings = new Map();
  let dynamic = 0;
  const insn = new OLD.JvmInsn();
  for (let i = fn.first; i < fn.first + Math.min(fn.count, 50000); i++) {
    o.insn(i, insn);
    if (!insn.op) continue;
    const pool = OLD.poolIndex(insn);
    if (insn.op.flags & OLD.F.CALL && insn.op.operand !== OLD.OPERAND.DYNAMIC) {
      const callee = o.callee(body.cls, pool);
      if (callee) calls.set(callee.addr, (calls.get(callee.addr) ?? 0) + 1);
    } else if (insn.op.flags & OLD.F.CALL) dynamic++;
    if (pool && cf.tags[pool] === OLD.CONSTANT.String) {
      const text = cf.utf8(cf.ref1(pool));
      strings.set(o.stringAddr(text), text);
    }
  }
  return [[...calls], dynamic, [...strings]];
}

function ourRefs(n, f) {
  const refs = n.functionRefs(f);
  const cls = n.bodies[f].cls;
  const calls = new Map();
  const strings = new Map();
  for (const pool of refs.calls) {
    const callee = n.callee(cls, pool);
    if (callee) calls.set(callee.addr, (calls.get(callee.addr) ?? 0) + 1);
  }
  for (const text of refs.strings) strings.set(n.stringAddr(text), text);
  return [[...calls], refs.dynamic, [...strings]];
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

let failed = 0;
let files = 0;
let threw = 0;
for (const file of args) {
  const bytes = new Uint8Array(readFileSync(file));
  await compareFile(basename(file), bytes);
  if (!damage) continue;
  let inner = bytes;
  if (inner[0] === 0x4a && inner[1] === 0x4d) inner = inner.subarray(4);
  const classes = OLD.isZip(inner) ? OLD.zipEntries(inner).filter((e) => e.name.endsWith('.class') && !e.name.startsWith('META-INF/')) : [];
  for (let k = 0; k < damage; k++) {
    const entry = classes.length ? classes[random() % classes.length] : undefined;
    const copy = (entry ? await OLD.zipRead(inner, entry) : bytes).slice();
    for (let f = 1 + (random() % 3); f > 0 && copy.length > 10; f--) copy[10 + (random() % (copy.length - 10))] ^= 1 << random() % 8;
    await compareFile(`${basename(file)} damaged #${k}`, copy, true);
  }
}

async function compareFile(name, bytes, quiet = false) {
  files++;
  const t0 = performance.now();
  let o;
  let oError;
  try {
    const { classes, container } = await OLD.readClasses(bytes);
    o = await OLD.analyzeJvm(classes, container);
  } catch (err) {
    oError = err.message;
  }
  let n;
  let nError;
  try {
    n = await NEW.analyzeJvm(bytes);
  } catch (err) {
    nError = err.message;
  }
  if (oError || nError) {
    const same = oError === nError;
    if (!same) failed++;
    if (!quiet || !same) console.log(`${name.padEnd(36)} ${same ? 'not read by either' : `DIFFERS: read: ${oError ?? 'ok'} / ${nError ?? 'ok'}`}`);
    n?.dispose();
    return;
  }
  const diffs = [];
  const tally = new Map();
  const first = new Map();
  const differ = (what, where, theirs, ours) => {
    tally.set(what, (tally.get(what) ?? 0) + 1);
    if (!first.has(what)) first.set(what, `${where}\n      TS:   ${theirs}\n      core: ${ours}`);
  };
  // `theirs` is a function: the TypeScript threw on a damaged class (read past its end) where
  // the core reads on; such a case is counted apart, not compared.
  const compare = (what, where, theirs, ours) => {
    let value;
    try {
      value = theirs();
    } catch {
      threw++;
      return;
    }
    const a = canon(value);
    const b = canon(ours());
    if (a !== b) differ(what, where, a, b);
  };
  let rows = 0;
  o.functions.forEach((fn, f) => {
    for (let i = fn.first; i < fn.first + fn.count; i++) {
      rows++;
      compare('rows', `${fn.name} #${i - fn.first}`, () => theirInsn(o, i, f), () => n.insn(i));
    }
    compare('method cards', fn.name, () => theirMethod(o, f), () => n.method(f));
    compare('function cards', fn.name, () => theirRefs(o, f), () => ourRefs(n, f));
  });
  o.classes.forEach((cf, k) => {
    compare('class cards', cf.name, () => theirClass(o, k), () => {
      const { fields, ...ours } = n.classView(k);
      return ours;
    });
    const info = n.classInfo[k];
    compare('class list', cf.name, () => [OLD.javaName(cf.name), OLD.modifiers(cf.access, 'class'), OLD.javaRelease(cf.major)], () => [info.java, info.modifiers, info.release]);
  });
  o.fields.forEach((field, k) => {
    const mods = OLD.modifiers(field.access, 'field');
    compare('fields', field.name, () => `${mods ? `${mods} ` : ''}${OLD.fieldType(field.descriptor)} ${OLD.javaName(o.classes[field.cls].name)}.${field.name}`, () => n.field(k)?.decl);
  });
  o.imported.forEach((m, k) => compare('imports', m.name, () => OLD.javaName(m.owner), () => n.imported[k]?.ownerJava));
  for (const s of o.strings) compare('strings', s.text, () => OLD.escapeString(s.text), () => n.escape(s.text));
  for (const [what, count] of tally) diffs.push(`${what} (${count})\n      ${first.get(what)}`);
  if (!quiet || diffs.length) console.log(`${name.padEnd(36)} ${String(rows).padStart(9)} rows  ${(performance.now() - t0).toFixed(0).padStart(7)} ms  ${diffs.length ? `DIFFERS: ${diffs.join('\n    ')}` : 'same'}`);
  if (diffs.length) failed++;
  n.dispose();
}
console.log(`${files} readings, ${failed} differ${threw ? `, ${threw} views of damaged classes the TypeScript threw on` : ''}`);
process.exit(failed ? 1 : 0);
