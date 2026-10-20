/**
 * Makes tests/fixtures/x86-hla-vectors.json: x86-64 instructions as the
 * HLA64 lifter reads them, with the lines the TypeScript lifter of the
 * original project (../html-disasm, or ORIGINAL) writes for them — alone and
 * as setter/consumer pairs, with no names and with names from a made-up
 * context — so the Rust lifter (crates/core/src/x86_hla.rs) is checked against
 * it without the original at hand.
 *
 *   node tools/x86-hla-vectors.mjs <x86-64 program …>
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { root } from './load.mjs';

const original = resolve(process.env.ORIGINAL ?? join(root, '..', 'html-disasm'));
const { load } = await import(join(original, 'tools', 'load.mjs'));
const M = await load('core/macho', 'core/elf', 'core/pe', 'core/image', 'core/x86/program', 'core/x86/hla');

/** Names that depend only on the address, so the Rust test can make the same ones (see fake() there). */
const fake = {
  target: (addr) => (addr % 7 === 0 ? { name: `f_${addr.toString(16)}`, kind: 'function' } : addr % 7 === 1 ? { name: `L${addr.toString(16)}`, kind: 'label' } : addr % 7 === 2 ? { name: `ns::g<${addr % 5}>`, kind: 'import' } : undefined),
  data: (addr) => (addr % 5 === 0 ? { kind: 'string', text: `s"\\${addr % 97}\n${'x'.repeat(addr % 90)}` } : addr % 5 === 1 ? { kind: 'string', text: 'objc', objc: true } : addr % 5 === 2 ? { kind: 'symbol', name: `sym_${addr % 11}` } : undefined),
  functionStart: (pc) => pc - (pc % 64),
  importAt: (addr) => (addr % 3 === 0 ? `imp_${addr % 13}` : undefined),
};
const bare = { target: () => undefined, data: () => undefined, functionStart: () => -1, importAt: () => undefined };

const out = [];
const shapes = new Map();
const view = (i) => ({ prefix: i.prefix, m: i.m, ops: i.ops, addr: i.addr, length: i.length, f: i.f, target: i.target ?? null, mem: i.mem ?? null });
for (const file of process.argv.slice(2)) {
  const bytes = new Uint8Array(readFileSync(file));
  let image;
  if (M.isElf(bytes)) image = M.fromElf(M.parseElf(bytes));
  else if (M.isPe(bytes)) image = M.fromPe(M.parsePe(bytes));
  else image = M.fromMachO(M.parseMachO(bytes, 'x86_64'));
  const p = await M.analyzeX86(image);
  if (p.mode !== 64) continue;
  for (let i = 0; i + 1 < p.totalInstructions; i++) {
    if (p.kinds[i] || p.kinds[i + 1]) continue;
    const a = p.insn(i);
    // Up to a few of each shape: mnemonic and the kinds of its operands.
    const shape = `${a.prefix}|${a.m}|${a.ops.replace(/0x[0-9a-f]+/g, 'N').replace(/\b[a-z]+\d*[a-z]?\b/g, (r) => (/ptr|byte|word|dword|qword|xmmword/.test(r) ? r : 'R'))}`;
    const seen = shapes.get(shape) ?? 0;
    const b = p.insn(i + 1);
    const pair = M.X86_SETTERS.has(a.m) && M.isX86Consumer(b.m);
    if (seen >= 3 && !(pair && seen < 12)) continue;
    shapes.set(shape, seen + 1);
    const lift = (x, ctx) => M.liftX86(x, ctx);
    const fuse = (ctx) => M.fuseX86(a, b, ctx) ?? null;
    out.push({ a: view(a), b: view(b), bare: lift(a, bare), named: lift(a, fake), fuseBare: fuse(bare), fuseNamed: fuse(fake) });
  }
}
writeFileSync(join(root, 'tests', 'fixtures', 'x86-hla-vectors.json'), JSON.stringify({ made: 'tools/x86-hla-vectors.mjs', vectors: out }));
console.log(`${out.length} vectors, ${shapes.size} shapes`);
