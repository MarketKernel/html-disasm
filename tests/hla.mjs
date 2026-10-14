/**
 * The HLA64 view: single instructions, the pairs it joins (a compare and its
 * branch or select, adrp and its add or load), and the whole fixture program
 * written out without a failure.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const { check, done } = checker();
const H = await load('core/arm64/decode', 'core/hla', 'core/macho', 'core/program', 'core/rows', 'core/image');

const PC = 0x100001000;
const names = new Map([
  [0x100000ff0, { name: 'L100000ff0', kind: 'label' }],
  [0x100002000, { name: 'helper', kind: 'function' }],
  [0x100003000, { name: 'printf', kind: 'import' }],
  [0x100004000, { name: 'core::fmt::Formatter::pad', kind: 'function' }],
]);
const ctx = {
  target: (addr) => names.get(addr),
  data: (addr) => (addr === 0x100834010 ? { kind: 'string', text: 'Hello, world!\n' } : undefined),
  functionStart: () => PC - 0x100,
};
const lift = (word, pc = PC) => H.liftOne(H.decode(word, pc), pc, ctx).text;
const pairOf = (a, b, pc = PC) => H.fuse(H.decode(a, pc), H.decode(b, pc + 4), ctx)?.text ?? null;
const branch = (op, target, pc) => (op | (((target - pc) / 4) & 0x3ffffff)) >>> 0;
const cond = (c, target, pc) => (0x54000000 | ((((target - pc) / 4) & 0x7ffff) << 5) | c) >>> 0;

const SINGLE = [
  [0x8b090d08, 'x8 += (x9 << 3)'],
  [0x39401c08, 'w8 = u8[x0 + 7]'],
  [0xf840867c, 'x28 = [x19++]'],
  [0xa9bf7bfd, 'push x29, x30'],
  [0xa8c17bfd, 'pop x29, x30'],
  [0xf90007ff, '[sp + 8] = 0'],
  [0xb9800016, 'x22 = i32[x0]'],
  [0x93407c08, 'x8 = sext32(w0)'],
  [0xd3609c08, 'x8 = (x0 >>> 32) & 0xff'],
  [0x9b0922e8, 'x8 = x8 + x23 * x9'],
  [0x9bca7d6a, 'x10 = umulh(x11, x10)'],
  [0x9ac10909, 'x9 = udiv(x8, x1)'],
  [0x52b00008, 'w8 = -0x80000000'],
  [0xf8690108, 'x8 = atomic_add(u64[x8], x9, release)'],
  [0xc8a8fe7f, 'x8 = cas(u64[x19], x8, 0, release)'],
  [0xc8dffef4, 'x20 = load_acquire(u64[x23])'],
  [0xc89ffee0, 'store_release(u64[x23], x0)'],
  // The writeback and SIMD&FP forms of FEAT_LRCPC3 stay instructions.
  [0x99c00a5b, 'ldapr w27, [x18], #4'],
  [0x99800ad2, 'stlr w18, [x22, #-4]!'],
  [0x1dc22a0f, 'ldapur q15, [x16, #0x22]'],
  [0x1e6e1001, 'd1 = 1.0'],
  [0x1e780008, 'w8 = int(d0)'],
  [0x1e620280, 'd0 = float(w20)'],
  [0x1f480020, 'd0 = d0 + d1 * d8'],
  [0xd63f0100, 'x8()'],
  [0xd61f0060, 'goto [x3]'],
  [0xd65f03c0, 'return'],
  [0xd4200020, 'trap(1)'],
  [0xd53b4210, 'mrs x16, NZCV'],
  [0xfa519822, 'ccmp x1, #0x11, #0x2, ls'],
  [0x9a9f0100, 'csel x0, x8, xzr, eq'],
  [0x4ee28420, 'add v0.2d, v1.2d, v2.2d'],
  [0x5ee28420, 'add d0, d1, d2'],
  [0x6ea0b820, 'neg v0.4s, v1.4s'],
  [0x1e622820, 'd0 = d1 + d2'],
  [0x4e62d420, 'fadd v0.2d, v1.2d, v2.2d'],
  [0x5e61d820, 'scvtf d0, d1'],
  [branch(0x94000000, 0x100002000, PC), 'helper()'],
  [branch(0x94000000, 0x100004000, PC), '`core::fmt::Formatter::pad`()'],
  [branch(0x14000000, 0x100003000, PC), 'return printf()'],
  [branch(0x14000000, 0x100000ff0, PC), 'goto L100000ff0'],
  [(0xb4000008 | ((((0x100000ff0 - PC) / 4) & 0x7ffff) << 5)) >>> 0, 'if x8 == 0 { goto L100000ff0 }'],
  [(0x36000008 | ((((0x100000ff0 - PC) / 4) & 0x3fff) << 5)) >>> 0, 'if w8 & 1 == 0 { goto L100000ff0 }'],
  [(0xb7f80000 | ((((0x100000ff0 - PC) / 4) & 0x3fff) << 5)) >>> 0, 'if x0 < 0 { goto L100000ff0 }'],
];
for (const [word, expected] of SINGLE) check(`lift ${word.toString(16)}`, lift(word), expected);

const CMP_X8_1 = 0xf100051f; // cmp x8, #0x1
check('cmp + b.ne', pairOf(CMP_X8_1, cond(1, 0x100000ff0, PC + 4)), 'if x8 != 1 { goto L100000ff0 }');
check('cmp + b.hs is unsigned', pairOf(CMP_X8_1, cond(2, 0x100000ff0, PC + 4)), 'if x8 >=u 1 { goto L100000ff0 }');
check('cmp + csel', pairOf(CMP_X8_1, 0x9a9f0100), 'x0 = x8 == 1 ? x8 : 0');
check('cmp + cset', pairOf(CMP_X8_1, 0x1a9f07e0), 'w0 = x8 != 1');
check('subs + b.ne tests the result', pairOf(0xf1000508, cond(1, 0x100000ff0, PC + 4)), 'x8 -= 1; if x8 != 0 { goto L100000ff0 }');
check('tst + b.ne', pairOf(0x721f011f, cond(1, 0x100000ff0, PC + 4)), 'if w8 & 2 != 0 { goto L100000ff0 }');
check('cmp + b.vs does not pair', pairOf(CMP_X8_1, cond(6, 0x100000ff0, PC + 4)), null);
const ADRP = 0xb0004161; // adrp x1, 0x100834000 at 0x10000724c
check('adrp + add makes the string', pairOf(ADRP, 0x91004021, 0x10000724c), 'x1 = "Hello, world!\\n"');
check('adrp + ldr reads through the page', pairOf(ADRP, 0xf9400821, 0x10000724c), 'x1 = [&data_100834010]');
check('pairedAddress', H.pairedAddress(H.decode(ADRP, 0x10000724c), H.decode(0x91004021, 0x100007250)), 0x100834010);
check('adrp and an unrelated add do not pair', pairOf(ADRP, 0x91004042, 0x10000724c), null);

// The whole fixture, line by line.
const image = H.parseMachO(new Uint8Array(readFileSync(join(root, 'tests', 'fixtures', 'hello'))));
const program = await H.analyze(H.fromMachO(image));
const asm = H.buildRows(program, 'asm');
const hla = H.buildRows(program, 'hla');
check('hla joins rows', hla.count < asm.count + program.functions.length, true);
check('every instruction has a row', [...asm.rowOfInsn].every((r) => r > 0) && [...hla.rowOfInsn].every((r) => r > 0), true);
const context = program.context();
const lines = [];
let failures = 0;
for (let r = 0; r < hla.count; r++) {
  if (hla.kind[r] !== 0) continue;
  const i = hla.value[r];
  const insn = program.insn(i);
  try {
    const line = program.flags[i] & 2 ? H.fuse(insn, program.insn(i + 1), context) : H.liftOne(insn, program.addrOf(i), context);
    if (!line?.text) failures++;
    else lines.push(line.text);
  } catch {
    failures++;
  }
}
check('every row lifts', failures, 0);
const text = lines.join('\n');
check('calls printf', text.includes('printf()'), true);
check('the atomic', /atomic_add\(u64\[x\d+\], x\d+, release\)/.test(text), true);
check('the format string', text.includes('"Hello, world! sum=%ld avg=%.2f kind=%s\\n"'), true);
check('switch strings', ['"zero"', '"many"'].every((s) => text.includes(s)) || text.includes('&data_'), true);

done('hla');
