/**
 * The HLA64 lines of real programs, made by this core (crates/core/src/arm64/hla.rs,
 * x86/hla.rs, asked in rounds through src/core/hla.ts) against the TypeScript lifter it
 * replaces (the original project, checked out beside this one, or ORIGINAL). Every
 * instruction is lifted alone and with the one after it, and on arm64 printed with its
 * targets named; the text, the words, the comment, whether the pair joined and where the
 * line's names lead must all be the same. Both sides get the same names: the context of
 * this project's analysis of the program. WebAssembly modules (.wasm) are compared too: every
 * statement the listing shows and every instruction alone, by WasmProgram.hla against the
 * original's liftGroup; so are .NET assemblies, by CilProgram.hla, and Java classes (a class
 * file, a JAR, a .jmod), by JvmProgram.hla. One difference is known and counted apart: an f32 constant the core
 * writes in its shortest digits where the TypeScript wrote one more (2^90, 2^87, 2^-96: see
 * decimal_float in crates/core/src/wasm/reader.rs) — the same float either way.
 *
 *   node tools/diff-hla.mjs <program …>
 */
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { load, root } from './load.mjs';

const original = resolve(process.env.ORIGINAL ?? join(root, '..', 'html-disasm'));
const { load: loadOriginal } = await import(join(original, 'tools', 'load.mjs'));
const NEW = await load('core/macho', 'core/elf', 'core/pe', 'core/image', 'core/program', 'core/x86/program', 'core/hla', 'core/x86/hla', 'core/wasm/module', 'core/wasm/program', 'core/cil/program', 'core/archive', 'core/jvm/program');
const OLD = await loadOriginal('core/arm64/decode', 'core/hla', 'core/x86/hla', 'core/wasm/module');
// Each bytecode lifter exports its own liftGroup: one bundle each, or the name is lost.
const OLD_WASM = await loadOriginal('core/wasm/hla');
// The original's .NET lifter reads its own program (the metadata it read), made by the original's analysis.
const OLD_CIL = await loadOriginal('core/cil/hla', 'core/cil/program', 'core/pe');
// The original's Java lifter reads its own program (all classes parsed): it is made by the
// original's analysis, which tools/diff-core.mjs checks gives the same instructions.
const OLD_JVM = await loadOriginal('core/jvm/hla', 'core/jvm/program', 'core/zip', 'core/jvm/classfile');
const SLICE = process.env.SLICE;

async function open(bytes) {
  const M = NEW;
  if (M.isWasm(bytes)) return M.analyzeWasm(M.parseWasm(bytes));
  if (M.isClassFile(bytes) || M.isJmod(bytes) || (M.isZip(bytes) && M.holdsClasses(M.zipNames(bytes)))) return M.analyzeJvm(bytes);
  if (M.isElf(bytes)) {
    const elf = M.parseElf(bytes);
    if (elf.machine === M.EM.AARCH64) return M.analyze(M.fromElf(elf));
    if (elf.machine === M.EM.X86_64) return M.analyzeX86(M.fromElf(elf));
    return null;
  }
  if (M.isPe(bytes)) {
    const pe = M.parsePe(bytes);
    if (pe.clr) return M.analyzeCil(pe);
    if (pe.machine === M.MACHINE.ARM64) return M.analyze(M.fromPe(pe));
    if (pe.machine === M.MACHINE.AMD64) return M.analyzeX86(M.fromPe(pe));
    return null;
  }
  let macho = M.parseMachO(bytes, SLICE);
  if (!SLICE && !/^arm64e?$/.test(macho.arch) && macho.arches.some((a) => a.name === 'arm64')) macho = M.parseMachO(bytes, 'arm64');
  if (/^arm64/.test(macho.arch)) return M.analyze(M.fromMachO(macho));
  if (macho.arch === 'x86_64') return M.analyzeX86(M.fromMachO(macho));
  return null;
}

/** The line as both sides should agree on it. */
const view = (line, fused, link) => JSON.stringify({ text: line.text, words: line.words, comment: line.comment ?? null, fused, link: link ?? null });

function compareArm64(p, ctx, report) {
  const total = p.totalInstructions;
  let prev = OLD.decode(p.words[0], p.addrOf(0));
  for (let i = 0; i < total; i++) {
    const word = p.words[i];
    const pc = p.addrOf(i);
    const insn = prev;
    const next = i + 1 < total ? { word: p.words[i + 1], pc: p.addrOf(i + 1) } : undefined;
    const nextInsn = next ? OLD.decode(next.word, next.pc) : undefined;
    prev = nextInsn;
    // Alone.
    const one = OLD.liftOne(insn, pc, ctx);
    const ours = NEW.liftArm64(word, pc, ctx);
    report(i, 'line', view(one, false, insn.target), view(ours, ours.fused, ours.link));
    // With the next one.
    if (nextInsn) {
      const pair = OLD.fuse(insn, nextInsn, ctx);
      const theirs = pair ? view(pair, true, insn.m === 'adrp' ? OLD.pairedAddress(insn, nextInsn) : nextInsn.target) : view(one, false, insn.target);
      const ourPair = NEW.liftArm64(word, pc, ctx, next);
      report(i, 'pair', theirs, view(ourPair, ourPair.fused, ourPair.link));
      report(i, 'paired', String(OLD.pairedAddress(insn, nextInsn)), String(NEW.pairedAddress(word, pc, next.word, next.pc)));
    }
    report(i, 'raw', OLD.rawInstruction(insn, ctx), NEW.rawInstruction(word, pc, ctx));
  }
}

function compareX86(p, ctx, report) {
  const total = p.totalInstructions;
  let insn = p.insn(0);
  for (let i = 0; i < total; i++) {
    const next = i + 1 < total ? p.insn(i + 1) : undefined;
    const one = OLD.liftX86(insn, ctx);
    const ours = NEW.liftX86(insn, ctx);
    report(i, 'line', view(one, false), view(ours, ours.fused));
    if (next) {
      const pair = OLD.fuseX86(insn, next, ctx);
      const ourPair = NEW.liftX86(insn, ctx, next);
      report(i, 'pair', pair ? view(pair, true) : view(one, false), view(ourPair, ourPair.fused));
    }
    insn = next;
  }
}

function compareWasm(p, report) {
  // The original's lifter reads the stack effects through the program, as it used to have them.
  const module = p.module;
  p.effects = {
    funcType: (func) => OLD.funcTypeOf(module, func),
    typeDef: (type) => module.types[type],
    tagParams: (tag) => {
      const type = module.tags[tag];
      return type === undefined ? 0 : (module.types[type]?.func?.params.length ?? 0);
    },
  };
  const names = { func: (index) => p.func(index)?.name ?? `func${index}` };
  const view = (line) => (line ? JSON.stringify({ text: line.text, words: line.words, comment: line.comment ?? null }) : 'null');
  for (let i = 0; i < p.totalInstructions; ) {
    const last = p.joinedTo(i);
    report(i, 'statement', view(OLD_WASM.liftGroup(p, i, last, names)), view(p.hla(i, last, names)));
    for (let k = i; k <= last; k++) report(k, 'alone', view(OLD_WASM.liftGroup(p, k, k, names)), view(p.hla(k, k, names)));
    i = last + 1;
  }
}

/** The text with every float literal (it has a point) read as an f32: the same for two spellings of one f32 constant. */
const asF32 = (text) => text.replace(/-?\d+\.\d+(?:e[+-]?\d+)?/g, (n) => String(Math.fround(Number(n))));

/** Each statement the listing shows, and each instruction of it alone, by a bytecode lifter of the original and the program's own. */
function compareGroups(p, report, old) {
  const view = (line) => (line ? JSON.stringify({ text: line.text, words: line.words }) : 'null');
  for (const f of p.functions) {
    for (let i = f.first; i < f.first + f.count; i++) {
      const first = i;
      while (p.flags[i] & 2 && i + 1 < f.first + f.count) i++;
      report(first, 'statement', view(old(p, first, i)), view(p.hla(first, i)));
      for (let k = first; k <= i && i > first; k++) report(k, 'alone', view(old(p, k, k)), view(p.hla(k, k)));
    }
  }
}

let failed = 0;
let lines = 0;
let floats = 0;
for (const file of process.argv.slice(2)) {
  let p;
  let bytes;
  try {
    bytes = new Uint8Array(readFileSync(file));
    p = await open(bytes);
  } catch (err) {
    console.log(`${file.split('/').pop().padEnd(32)} cannot open: ${err.message}`);
    continue;
  }
  if (!p || !p.totalInstructions || (p.arch === 'x86' && p.mode !== 64)) continue;
  const ctx = p.arch === 'wasm' || p.arch === 'cil' || p.arch === 'jvm' ? null : p.context();
  const t0 = performance.now();
  const kinds = new Map();
  const report = (i, kind, theirs, ours) => {
    lines++;
    if (theirs === ours) return;
    if (asF32(theirs) === asF32(ours)) {
      floats++;
      return;
    }
    const k = kinds.get(kind) ?? { count: 0, first: null };
    k.count++;
    k.first ??= { i, theirs, ours };
    kinds.set(kind, k);
  };
  if (p.arch === 'wasm') compareWasm(p, report);
  else if (p.arch === 'cil') {
    const o = await OLD_CIL.analyzeCil(OLD_CIL.parsePe(bytes));
    compareGroups(p, report, (_, first, last) => OLD_CIL.liftGroup(o, first, last));
  }
  else if (p.arch === 'jvm') {
    const { classes, container } = await OLD_JVM.readClasses(bytes);
    const o = await OLD_JVM.analyzeJvm(classes, container);
    compareGroups(p, report, (_, first, last) => OLD_JVM.liftGroup(o, first, last));
  }
  else if (p.arch === 'x86') compareX86(p, ctx, report);
  else compareArm64(p, ctx, report);
  const ms = (performance.now() - t0).toFixed(0);
  if (!kinds.size) {
    console.log(`${file.split('/').pop().padEnd(32)} ${String(p.totalInstructions).padStart(9)} insns  ${ms.padStart(7)} ms  same`);
    continue;
  }
  failed++;
  p.dispose?.();
  console.log(`${file.split('/').pop().padEnd(32)} ${String(p.totalInstructions).padStart(9)} insns  DIFFERS: ${[...kinds].map(([k, v]) => `${k} ${v.count}`).join(', ')}`);
  for (const [kind, { first }] of kinds) console.log(`  ${kind} at ${first.i} (${p.addrOf(first.i).toString(16)}):\n    TS   ${first.theirs}\n    core ${first.ours}`);
}
console.log(`${lines} lines compared, ${failed} programs differ${floats ? `, ${floats} f32 constants in shorter digits` : ''}`);
process.exit(failed ? 1 : 0);
