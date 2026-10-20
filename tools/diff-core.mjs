/**
 * The analysis of real programs by this core against the TypeScript core it
 * replaces (the original project, checked out beside this one, or ORIGINAL):
 * the instructions, flags, functions, cross references and strings must be
 * the same, and the time each took is printed. Java classes (a class file, a
 * JAR, a .jmod) are compared too: the instructions, the functions, every
 * reference, the classes, fields, handlers and what each constant the code
 * names leads to. So are WebAssembly modules: the instructions, their depth
 * and branches, the functions, imports, segments, strings and every map; and
 * .NET assemblies: the instructions, labels and regions, functions, imports,
 * P/Invokes and every reference.
 *
 *   node tools/diff-core.mjs <program …>
 */
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { load, root } from './load.mjs';

const original = resolve(process.env.ORIGINAL ?? join(root, '..', 'html-disasm'));
const { load: loadOriginal } = await import(join(original, 'tools', 'load.mjs'));
const modules = ['core/macho', 'core/elf', 'core/pe', 'core/image', 'core/program', 'core/x86/program', 'core/arm32/program', 'core/jvm/program', 'core/wasm/module', 'core/wasm/program', 'core/cil/program'];
// SLICE=x86_64 (or arm64, armv7…) picks the slice of a universal Mach-O file.
const SLICE = process.env.SLICE;
const NEW = await load(...modules, 'core/archive');
const OLD = await loadOriginal(...modules, 'core/zip', 'core/jvm/classfile', 'core/jvm/decode');

/** The analysis main.ts would run for a native program. */
async function analyze(M, bytes) {
  const t0 = performance.now();
  let image;
  let run;
  if (M.isElf(bytes)) {
    const elf = M.parseElf(bytes);
    image = M.fromElf(elf);
    run = elf.machine === M.EM.ARM ? M.analyzeArm32 : elf.machine === M.EM.AARCH64 ? M.analyze : M.analyzeX86;
  } else if (M.isPe(bytes)) {
    const pe = M.parsePe(bytes);
    image = M.fromPe(pe);
    run = pe.machine === M.MACHINE.ARM64 ? M.analyze : pe.machine === M.MACHINE.ARMNT ? M.analyzeArm32 : M.analyzeX86;
  } else {
    let macho = M.parseMachO(bytes, SLICE);
    if (!SLICE && !/^arm64e?$/.test(macho.arch) && macho.arches.some((a) => a.name === 'arm64')) macho = M.parseMachO(bytes, 'arm64');
    image = M.fromMachO(macho);
    run = /^arm64/.test(macho.arch) ? M.analyze : /^(x86_64|i386)$/.test(macho.arch) ? M.analyzeX86 : M.analyzeArm32;
  }
  const t1 = performance.now();
  const p = await run(image);
  return { p, parse: t1 - t0, analyze: performance.now() - t1 };
}

const mapJson = (m) => (m ? JSON.stringify([...m.entries()].sort((a, b) => a[0] - b[0])) : String(m));
const isJava = (M, bytes) => M.isClassFile(bytes) || M.isJmod(bytes) || (M.isZip(bytes) && M.holdsClasses(M.zipEntries(bytes).map((e) => e.name)));

/** The Java analysis, the original's (classes read first, then the pass) against this core's. */
async function compareJvm(file, bytes) {
  const t0 = performance.now();
  const { classes, container } = await OLD.readClasses(bytes);
  const o = await OLD.analyzeJvm(classes, container);
  const t1 = performance.now();
  const n = await NEW.analyzeJvm(bytes);
  const t2 = performance.now();
  const diffs = [];
  const same = (name, x, y) => {
    if (x !== y) diffs.push(name);
  };
  same('total', o.totalInstructions, n.totalInstructions);
  let mn = 0;
  let fl = 0;
  let br = 0;
  for (let i = 0; i < o.totalInstructions; i++) {
    if (o.mnemonics[o.mnemonicIds[i]] !== n.mnemonics[n.mnemonicIds[i]]) mn++;
    if (o.flags[i] !== n.flags[i]) fl++;
    if (o.offsets[i] !== n.offsets[i] || JSON.stringify(o.branchTargets(i)) !== JSON.stringify(n.branchTargets(i))) br++;
  }
  same(`mnemonics (${mn} differ)`, mn, 0);
  same(`flags (${fl} differ)`, fl, 0);
  same(`offsets and branches (${br} differ)`, br, 0);
  same('counts', JSON.stringify(o.counts), JSON.stringify(n.counts));
  same('functions', JSON.stringify(o.functions), JSON.stringify(n.functions));
  same('ranges', JSON.stringify(o.ranges), JSON.stringify(n.ranges));
  same('callers', mapJson(o.callers), mapJson(n.callers));
  same('dataRefs', mapJson(o.dataRefs), mapJson(n.dataRefs));
  same('fieldRefs', mapJson(o.fieldRefs), mapJson(n.fieldRefs));
  same('strings', JSON.stringify(o.strings), JSON.stringify(n.strings));
  // The core also names the owner as Java writes it, for the page (diff-jvm-page.mjs compares it).
  same('imported', JSON.stringify(o.imported), JSON.stringify(n.imported.map(({ ownerJava, ...m }) => m)));
  same('entry', o.entry?.addr, n.entry?.addr);
  same('version', JSON.stringify(o.version), JSON.stringify(n.version));
  same('kotlin', o.kotlin, n.kotlin);
  same('dynamicCalls', o.dynamicCalls, n.dynamicCalls);
  same('container', JSON.stringify({ ...o.container, manifest: [...o.container.manifest] }), JSON.stringify({ ...n.container, manifest: [...n.container.manifest] }));
  const summary = (cf) => [cf.name, cf.path, OLD.classKind(cf), cf.access, cf.major, cf.minor, cf.sourceFile() ?? null];
  same('classes', JSON.stringify(classes.map(summary)), JSON.stringify(n.classInfo.map((c) => [c.name, c.path, c.kind, c.access, c.major, c.minor, c.source])));
  same('bodies', JSON.stringify(o.bodies.map((b) => [b.cls, b.base, b.method.access, b.code.offset, b.code.length])), JSON.stringify(n.bodies.map((b) => [b.cls, b.base, b.access, b.codeOffset, b.codeLength])));
  same('field count', o.fields.length, n.fieldCount);
  let fields = 0;
  let regions = 0;
  let refs = 0;
  let regionCount = 0;
  for (let k = 0; k < o.fields.length; k++) {
    // The core also writes the declaration, for the page; diff-jvm-page.mjs compares it.
    const { decl, ...field } = n.field(k) ?? {};
    if (JSON.stringify(o.fields[k]) !== JSON.stringify(field)) fields++;
  }
  o.functions.forEach((fn, f) => {
    const body = o.bodies[f];
    for (let i = fn.first; i < fn.first + fn.count; i++) {
      // A handler's catch is a class name on the core's side, for the page (diff-jvm-page.mjs compares it).
      const theirs = (o.regions.get(i) ?? []).map(({ handler: { start, end, handler }, part }) => ({ handler: { start, end, handler }, part }));
      const ours = n.regionsAt(i).map(({ handler: { start, end, handler }, part }) => ({ handler: { start, end, handler }, part }));
      if (ours.length) regionCount++;
      if (JSON.stringify(theirs) !== JSON.stringify(ours)) regions++;
      const insn = o.insn(i);
      const pool = OLD.poolIndex(insn);
      if (!pool || !insn.op) continue;
      const cf = classes[body.cls];
      if (insn.op.flags & 4) {
        if (o.callee(body.cls, pool)?.addr !== n.callee(body.cls, pool)?.addr) refs++;
        if (insn.m === 'invokedynamic') {
          for (const arg of cf.bootstrapMethods()[cf.dynamic(pool).bootstrap]?.args ?? []) if (o.callee(body.cls, arg)?.addr !== n.callee(body.cls, arg)?.addr) refs++;
        }
      } else if (/^(get|put)(field|static)$/.test(insn.m)) {
        if (o.fieldAddr(body.cls, pool) !== n.fieldAddr(body.cls, pool)) refs++;
      } else if (cf.tags[pool] === OLD.CONSTANT.MethodHandle && o.callee(body.cls, pool)?.addr !== n.callee(body.cls, pool)?.addr) refs++;
    }
  });
  same(`fields (${fields} differ)`, fields, 0);
  same(`regions (${regions} differ)`, regions, 0);
  same('instructions with regions', o.regions.size, regionCount);
  same(`references (${refs} differ)`, refs, 0);
  const t = (x) => x.toFixed(0).padStart(6);
  console.log(`${file.split('/').pop().padEnd(28)} ${String(o.totalInstructions).padStart(9)} insns  TS ${t(t1 - t0)} ms  core ${t(t2 - t1)} ms  ×${((t1 - t0) / (t2 - t1)).toFixed(1)}  ${diffs.length ? `DIFFERS: ${diffs.join(', ')}` : 'same'}`);
  n.dispose();
  return diffs.length === 0;
}

/** The WebAssembly analysis, the original's against this core's, on the same reading of the module. */
async function compareWasm(file, bytes) {
  const t0 = performance.now();
  const o = await OLD.analyzeWasm(OLD.parseWasm(bytes));
  const t1 = performance.now();
  const n = await NEW.analyzeWasm(NEW.parseWasm(bytes));
  const t2 = performance.now();
  const diffs = [];
  const same = (name, x, y) => {
    if (x !== y) diffs.push(name);
  };
  same('total', o.totalInstructions, n.totalInstructions);
  let mn = 0;
  let fl = 0;
  let br = 0;
  for (let i = 0; i < o.totalInstructions; i++) {
    if (o.mnemonics[o.mnemonicIds[i]] !== n.mnemonics[n.mnemonicIds[i]]) mn++;
    if (o.flags[i] !== n.flags[i]) fl++;
    if (o.offsets[i] !== n.offsets[i] || o.depth[i] !== n.depth[i] || JSON.stringify(o.branchTargets(i)) !== JSON.stringify(n.branchTargets(i))) br++;
  }
  same(`mnemonics (${mn} differ)`, mn, 0);
  same(`flags (${fl} differ)`, fl, 0);
  same(`offsets, depth and branches (${br} differ)`, br, 0);
  same('branches', o.targets.size, n.targetIndex.length);
  same('counts', JSON.stringify(o.counts), JSON.stringify(n.counts));
  same('functions', JSON.stringify(o.functions), JSON.stringify(n.functions));
  same('functionAtIndex', mapJson(o.functionAtIndex), mapJson(n.functionAtIndex));
  same('byIndex', JSON.stringify(o.byIndex), JSON.stringify(n.byIndex));
  same('bodies', JSON.stringify(o.bodies), JSON.stringify(n.bodies));
  same('imported', JSON.stringify(o.imported), JSON.stringify(n.imported));
  same('ranges', JSON.stringify(o.ranges), JSON.stringify(n.ranges));
  same('segments', JSON.stringify(o.segments), JSON.stringify(n.segments));
  same('strings', JSON.stringify(o.strings), JSON.stringify(n.strings));
  same('stringAt', mapJson(o.stringAt), mapJson(n.stringAt));
  for (const key of ['callers', 'dataRefs', 'refFuncs', 'globalRefs', 'indirect', 'lengthAt']) same(key, mapJson(o[key]), mapJson(n[key]));
  same('valueBranches', JSON.stringify([...o.valueBranches].sort((a, b) => a - b)), JSON.stringify([...n.valueBranches]));
  same('indirectCalls', o.indirectCalls, n.indirectCalls);
  same('lines', JSON.stringify(o.lines), JSON.stringify(n.lines));
  const t = (x) => x.toFixed(0).padStart(6);
  console.log(`${file.split('/').pop().padEnd(28)} ${String(o.totalInstructions).padStart(9)} insns  TS ${t(t1 - t0)} ms  core ${t(t2 - t1)} ms  ×${((t1 - t0) / (t2 - t1)).toFixed(1)}  ${diffs.length ? `DIFFERS: ${diffs.join(', ')}` : 'same'}`);
  return diffs.length === 0;
}

/** The .NET analysis, the original's against this core's. */
async function compareCil(file, bytes) {
  const t0 = performance.now();
  const o = await OLD.analyzeCil(OLD.parsePe(bytes));
  const t1 = performance.now();
  const n = await NEW.analyzeCil(NEW.parsePe(bytes));
  const t2 = performance.now();
  const diffs = [];
  const same = (name, x, y) => {
    if (x !== y) diffs.push(name);
  };
  same('total', o.totalInstructions, n.totalInstructions);
  let mn = 0;
  let fl = 0;
  let br = 0;
  let rg = 0;
  for (let i = 0; i < o.totalInstructions; i++) {
    if (o.mnemonics[o.mnemonicIds[i]] !== n.mnemonics[n.mnemonicIds[i]]) mn++;
    if (o.flags[i] !== n.flags[i]) fl++;
    if (o.offsets[i] !== n.offsets[i] || JSON.stringify(o.branchTargets(i)) !== JSON.stringify(n.branchTargets(i))) br++;
    // The core's regions name a clause by its place in its method's body.
    const theirs = o.regions.get(i)?.map(({ clause, part }) => ({ clause: o.bodyOf(i).clauses.indexOf(clause), part }));
    if (JSON.stringify(theirs) !== JSON.stringify(n.regions.get(i))) rg++;
  }
  same(`mnemonics (${mn} differ)`, mn, 0);
  same(`flags (${fl} differ)`, fl, 0);
  same(`offsets and branches (${br} differ)`, br, 0);
  same(`regions (${rg} differ)`, rg, 0);
  same('regions', o.regions.size, n.regions.size);
  same('branches', o.targets.size, n.targetIndex.length);
  same('counts', JSON.stringify(o.counts), JSON.stringify(n.counts));
  same('functions', JSON.stringify(o.functions), JSON.stringify(n.functions));
  same('functionAtIndex', mapJson(o.functionAtIndex), mapJson(n.functionAtIndex));
  same('methodFn', mapJson(o.methodFn), mapJson(n.methodFn));
  // The bodies' headers and clauses: tools/diff-cil-page.mjs compares the cards made of them.
  same('code bytes', o.bodies.reduce((k, b) => k + b.size, 0), n.codeBytes);
  same('framework, entry', JSON.stringify([o.assemblyName, o.framework, o.entryMethod, o.archLabel(), o.platformLabel()]), JSON.stringify([n.assemblyName, n.framework, n.entryMethod, n.archLabel(), n.platformLabel()]));
  same('ranges', JSON.stringify(o.ranges), JSON.stringify(n.ranges));
  same('imported', JSON.stringify(o.imported), JSON.stringify(n.imported));
  same('pinvokes', JSON.stringify(o.pinvokes), JSON.stringify(n.pinvokes));
  same('strings', JSON.stringify(o.strings), JSON.stringify(n.strings));
  for (const key of ['callers', 'dataRefs', 'fieldRefs', 'typeRefs']) same(key, mapJson(o[key]), mapJson(n[key]));
  same('indirectCalls', o.indirectCalls, n.indirectCalls);
  const t = (x) => x.toFixed(0).padStart(6);
  console.log(`${file.split('/').pop().padEnd(28)} ${String(o.totalInstructions).padStart(9)} insns  TS ${t(t1 - t0)} ms  core ${t(t2 - t1)} ms  ×${((t1 - t0) / (t2 - t1)).toFixed(1)}  ${diffs.length ? `DIFFERS: ${diffs.join(', ')}` : 'same'}`);
  return diffs.length === 0;
}

let failed = 0;
for (const file of process.argv.slice(2)) {
  const bytes = new Uint8Array(readFileSync(file));
  if (OLD.isWasm(bytes)) {
    if (!(await compareWasm(file, bytes))) failed++;
    continue;
  }
  if (OLD.isPe(bytes) && OLD.parsePe(bytes).clr) {
    if (!(await compareCil(file, bytes))) failed++;
    continue;
  }
  if (isJava(OLD, bytes)) {
    if (!(await compareJvm(file, bytes))) failed++;
    continue;
  }
  let a;
  try {
    a = await analyze(OLD, bytes);
  } catch (err) {
    // What the original cannot open has nothing to be compared with.
    console.log(`${file.split('/').pop().padEnd(28)} skipped: ${err.message}`);
    continue;
  }
  let b;
  try {
    b = await analyze(NEW, bytes);
  } catch (err) {
    console.log(`${file.split('/').pop().padEnd(28)} DIFFERS: the core failed (${err.message})`);
    failed++;
    continue;
  }
  const diffs = [];
  const same = (name, x, y) => {
    if (x !== y) diffs.push(name);
  };
  const { p: o } = a;
  const { p: n } = b;
  same('total', o.totalInstructions, n.totalInstructions);
  let mn = 0;
  let fl = 0;
  for (let i = 0; i < o.totalInstructions; i++) {
    if (o.mnemonics[o.mnemonicIds[i]] !== n.mnemonics[n.mnemonicIds[i]]) mn++;
    if (o.flags[i] !== n.flags[i]) fl++;
  }
  same(`mnemonics (${mn} differ)`, mn, 0);
  same(`flags (${fl} differ)`, fl, 0);
  same('counts', JSON.stringify(o.counts), JSON.stringify(n.counts));
  same('functions', JSON.stringify(o.functions), JSON.stringify(n.functions));
  same('callers', mapJson(o.callers), mapJson(n.callers));
  same('dataRefs', mapJson(o.dataRefs), mapJson(n.dataRefs));
  same('slotCallers', mapJson(o.slotCallers), mapJson(n.slotCallers));
  same('slotCalls', mapJson(o.slotCalls), mapJson(n.slotCalls));
  same('lengthAt', mapJson(o.lengthAt), mapJson(n.lengthAt));
  same('strings', JSON.stringify(o.strings), JSON.stringify(n.strings));
  // What an architecture adds: per-instruction arrays and maps of its own.
  for (const key of Object.keys(o)) {
    if (['image', 'baseValues', 'decodeMs', 'mnemonicIds', 'flags', 'mnemonics', 'counts', 'functions', 'callers', 'dataRefs', 'slotCallers', 'slotCalls', 'lengthAt', 'strings', 'stringAt', 'functionAtIndex'].includes(key)) continue;
    const a = o[key];
    const b = n[key];
    const text = (v) => (v instanceof Map ? mapJson(v) : ArrayBuffer.isView(v) ? Array.from(v).join(',') : JSON.stringify(v));
    same(key, text(a), text(b));
  }
  const t = (x) => x.toFixed(0).padStart(6);
  console.log(`${file.split('/').pop().padEnd(28)} ${String(o.totalInstructions).padStart(9)} insns  TS ${t(a.analyze)} ms  core ${t(b.analyze)} ms  ×${(a.analyze / b.analyze).toFixed(1)}  ${diffs.length ? `DIFFERS: ${diffs.join(', ')}` : 'same'}`);
  if (diffs.length) failed++;
}
if (failed) process.exit(1);
