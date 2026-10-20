/**
 * WebAssembly: the decoder against fixed vectors (the text wasm-tools prints,
 * made by `node tools/verify-wasm.mjs … --vectors`), the module reader and
 * the analysis on tests/fixtures/hello.wasm — the same hello.c as the arm64
 * fixture, built with Emscripten 5.0.7:
 *
 *   emcc -O1 -g2 -gline-tables-only -matomics -mbulk-memory -sSHARED_MEMORY hello.c -o hello.wasm
 *
 * (shared memory gives real atomics, and passive data the start function
 * places), and the HLA64 view on it and on small modules built here.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const { check, done } = checker();
const W = await load('core/wasm/module', 'core/wasm/decode', 'core/wasm/program', 'core/wasm/hla', 'core/demangle');

/* ---------------- the decoder ---------------- */

const { vectors } = JSON.parse(readFileSync(join(root, 'tests', 'fixtures', 'wasm-vectors.json'), 'utf8'));
let wrong = 0;
for (const [hexBytes, text] of vectors) {
  const bytes = Uint8Array.from(Buffer.from(hexBytes, 'hex'));
  const insn = W.decodeBytes(bytes);
  const got = W.formatInsn(insn);
  if (got !== text || insn.len !== bytes.length) {
    if (wrong++ < 20) check(`${hexBytes}`, [got, insn.len], [text, bytes.length]);
  }
}
check(`all ${vectors.length} vectors match wasm-tools`, wrong, 0);

const decode = (...bytes) => W.decodeBytes(Uint8Array.from(bytes));
check('an unknown opcode takes the rest of the body', [decode(0xff, 1, 2).m, decode(0xff, 1, 2).len], ['.bytes', 3]);
check('redundant LEB128', W.formatInsn(decode(0x41, 0x80, 0x80, 0x80, 0x80, 0x00)), 'i32.const 0');
check('i64.const, 64 bits', W.formatInsn(decode(0x42, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f)), 'i64.const -9223372036854775808');
check('memarg with a memory index', W.formatInsn(decode(0x28, 0x42, 0x01, 0x08)), 'i32.load 1 offset=8');

// Floats as wasm-tools writes them (hex, and Rust's shortest decimal in a comment): cases_of_tests_wasm_mjs in crates/core/tests/wasm.rs.

/* ---------------- the module ---------------- */

const bytes = new Uint8Array(readFileSync(join(root, 'tests', 'fixtures', 'hello.wasm')));
const module = W.parseWasm(bytes);
check('no warnings', module.warnings, []);
check('sections in order', module.sections.filter((s) => s.id).map((s) => s.name), ['type', 'import', 'function', 'table', 'memory', 'global', 'export', 'start', 'element', 'data count', 'code', 'data']);
check('imports', module.imports.map((i) => `${i.module}.${i.name}`).includes('wasi_snapshot_preview1.fd_write'), true);
check('exports _start', module.exports.some((e) => e.name === '_start' && e.kind === 'func'), true);
check('shared memory', module.memories[0]?.limits.shared, true);
check('passive data', module.data.every((d) => d.mode === 'passive'), true);
check('module name', module.names.module, 'hello.wasm');
check('function names', ['sum', 'kind', 'average', 'main'].every((name) => [...module.names.functions.values()].includes(name)), true);
check('target features', module.features.some((f) => f.name === 'atomics'), true);
check('DWARF sections', module.debug.has('.debug_line'), true);
check('not a module', (() => { try { W.parseWasm(new Uint8Array(16)); return 'read'; } catch (err) { return err instanceof W.NotWasm; } })(), true);
check('a component is refused', (() => { try { W.parseWasm(Uint8Array.from([0, 0x61, 0x73, 0x6d, 0x0d, 0, 1, 0])); return 'read'; } catch (err) { return /component/.test(err.message); } })(), true);

/* ---------------- the analysis ---------------- */

const p = await W.analyzeWasm(module);
const fnNamed = (name) => p.functions.find((f) => f.name === name);
const main = fnNamed('main');
check('functions with code', p.functions.length, module.bodies.length);
check('opens at main', W.entryOf(p)?.name, 'main');
check('start function', p.functions.find((f) => f.kind === 'entry')?.name, '__wasm_init_memory');
check('_start exported', fnNamed('_start')?.kind, 'export');
check('C names keep their underscores', !!fnNamed('__wasm_call_ctors'), true);
check('imports are functions without code', p.imported.map((f) => f.name).includes('fd_write') || p.imported.map((f) => f.name).includes('__wasi_fd_write'), true);
check('passive segments placed by the start function', p.segments.length > 0 && p.segments.every((s) => s.passive) && p.segments[0].addr >= 1024, true);
const strings = p.strings.map((s) => s.text);
check('the format string', strings.includes('Hello, world! sum=%ld avg=%.2f kind=%s\n'), true);
check('--help', strings.includes('--help'), true);
const counter = [...p.dataRefs.keys()].find((addr) => p.dataRefs.get(addr).length >= 2 && !p.segmentAt(addr));
check('the atomic counter is a data reference', counter !== undefined, true);
check('sum is called twice', p.callers.get(fnNamed('sum').addr)?.length, 2);
check('offsets ascend', p.offsets.every((o, i) => i === 0 || o > p.offsets[i - 1]), true);
check('indexOf finds every offset', [0, 100, p.totalInstructions - 1].every((i) => p.indexOf(p.addrOf(i)) === i), true);
check('labels', p.flags.some((f) => f & 1), true);
check('source line of main', p.lineOf(main.first), { file: 'hello.c', line: 32, column: 0 });
check('atomics counted', p.counts.some((c) => c.mnemonic === 'i32.atomic.rmw.add'), true);

/* ---------------- HLA64 ---------------- */

const naming = { func: (index) => p.func(index)?.name ?? `func${index}` };
const linesOf = (q, fn, names = { func: (index) => q.func(index)?.name ?? `func${index}` }) => {
  const out = [];
  for (let i = fn.first; i < fn.first + fn.count; ) {
    let j = i;
    while (q.flags[j] & 2 && j + 1 < fn.first + fn.count) j++;
    const line = q.hla(i, j, names);
    out.push(line ? W.plain(line.text) : null);
    i = j + 1;
  }
  return out;
};
let unwritten = 0;
for (const fn of p.functions) {
  for (let i = fn.first; i < fn.first + fn.count; ) {
    let j = i;
    while (p.flags[j] & 2 && j + 1 < fn.first + fn.count) j++;
    if (j > i && !p.hla(i, j, naming)) unwritten++;
    i = j + 1;
  }
}
const mainLines = linesOf(p, main);
check('main: the atomic', mainLines.includes('atomic_add(u32[0x770], l0, seq_cst)'), true);
check('main: a call with arguments', mainLines.includes('l3 = sum(0x4b0, 8)'), true);
check('main: printf with its string', mainLines.includes('__small_printf("Hello, world! sum=%ld avg=%.2f kind=%s\\n", l2)'), true);
check('main: the condition and its branch', mainLines.some((l) => /^if strcmp\(i32\[l1 \+ 4\], "--help"\) \{ goto L[0-9a-f]+ \}$/.test(l ?? '')), true);
check('main: the stack pointer', mainLines[0], '__stack_pointer = (l2 = __stack_pointer - 0x20)');
check('main: returns a comparison', mainLines.at(-1), 'return l0 > 0x64');
check('average', linesOf(p, fnNamed('average')).at(-1), 'return f64(sum(l0, l1)) / f64(l1)');
check('kind: a string address', linesOf(p, fnNamed('kind'))[0], 'l1 = "many"');
const call = p.hla(p.indexOf(0x3fd), p.indexOf(0x40b), naming);
check('marks are links', W.parts(call?.text ?? '').map((part) => [part.kind ?? '', part.text]), [['v', 'l3'], ['', ' = '], ['f', 'sum'], ['', '(0x4b0, 8)']]);

/* Small modules built here: what the view does with forms the fixture lacks. */
const leb = (n) => {
  const out = [];
  do {
    let b = n & 0x7f;
    n >>>= 7;
    if (n) b |= 0x80;
    out.push(b);
  } while (n);
  return out;
};
const section = (id, content) => [id, ...leb(content.length), ...content];
const vec = (items) => [...leb(items.length), ...items.flat()];
const I32 = 0x7f;
/** A module of one (i32, i32) -> i32 function with `locals` extra i32 locals and this code, plus a table. */
function moduleOf(code, locals = 0) {
  const body = [...vec(locals ? [[locals, I32]] : []), ...code, 0x0b];
  return Uint8Array.from([
    0, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
    ...section(1, vec([[0x60, ...vec([[I32], [I32]]), ...vec([[I32]])]])),
    ...section(3, vec([[0]])),
    ...section(4, vec([[0x70, 0, 1]])),
    ...section(10, vec([[...leb(body.length), ...body]])),
  ]);
}
async function lift(code, locals = 0) {
  const q = await W.analyzeWasm(W.parseWasm(moduleOf(code, locals)));
  return linesOf(q, q.functions[0]);
}
check('select of plain values is ?:', await lift([0x20, 0, 0x20, 1, 0x20, 0, 0x41, 5, 0x48, 0x1b]), ['return l0 < 5 ? l0 : l1']);
check('select with a call keeps its order', await lift([0x20, 0, 0x20, 1, 0x10, 0, 0x20, 1, 0x20, 0, 0x1b]), ['return select(func0(l0, l1), l1, l0)']);
check('compound assignment', await lift([0x20, 0, 0x41, 1, 0x6a, 0x21, 0, 0x41, 0]), ['l0 += 1', 'return 0']);
check('shifts get parentheses', await lift([0x20, 0, 0x20, 1, 0x41, 2, 0x74, 0x6a]), ['return l0 + (l1 << 2)']);
check('unsigned compare and udiv', await lift([0x20, 0, 0x20, 1, 0x6e, 0x41, 10, 0x49]), ['return udiv(l0, l1) <u 0xa']);
check('a call through the table', await lift([0x20, 0, 0x20, 1, 0x20, 0, 0x11, 0, 0]), ['return table0[l0](l0, l1)']);
check('if and else', await lift([0x20, 0, 0x45, 0x04, 0x40, 0x41, 1, 0x21, 2, 0x05, 0x41, 2, 0x21, 2, 0x0b, 0x20, 2], 1), ['if l0 == 0 {', 'l2 = 1', '} else {', 'l2 = 2', '}', 'return l2']);
const switched = await lift([0x02, 0x40, 0x02, 0x40, 0x02, 0x40, 0x20, 0, 0x0e, 4, 0, 1, 0, 1, 2, 0x0b, 0x0b, 0x0b, 0x41, 0]);
check('br_table is a switch', /^switch l0 \{ case 0, 2 \{ goto L\w+ \} case 1, 3 \{ goto L\w+ \} default \{ goto L\w+ \} \}$/.test(switched.find((l) => l?.startsWith('switch')) ?? ''), true);
check('a local.tee inside', await lift([0x20, 0, 0x22, 2, 0x20, 2, 0x6c], 1), ['return (l2 = l0) * l2']);
check('a stray value stays an instruction', (await lift([0x20, 0, 0x02, 0x40, 0x0b]))[0], null);
check('every group of hello.wasm reads as one line', unwritten, 0);

/* ---------------- names ---------------- */

check('Rust v0 in a module', W.demangleWasm('_RNvCs1234_7mycrate4main').short, 'mycrate::main');
check('Rust legacy in a module', W.demangleWasm('_ZN4core3fmt5write17h0123456789abcdefE').short, 'core::fmt::write');
check('C names stay', W.demangleWasm('__wasm_call_ctors').short, '__wasm_call_ctors');

done('wasm');
