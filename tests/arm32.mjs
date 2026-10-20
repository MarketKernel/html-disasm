/**
 * The AArch32 decoder against fixed vectors: thousands of A32 and T32
 * instructions with the exact text llvm-objdump prints for them
 * (tests/fixtures/arm32-vectors.json, made by `node tools/verify-arm32.mjs …
 * --vectors`), and the structure behind a few: branch targets and the
 * instruction set they lead to, literal addresses, IT blocks, flags, sizes.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const { check, done } = checker();
const D = await load('core/arm32/decode', 'core/arm32/types');
const F = D.F;

const { vectors } = JSON.parse(readFileSync(join(root, 'tests', 'fixtures', 'arm32-vectors.json'), 'utf8'));
let wrong = 0;
for (const [encoding, pc, text, wide] of vectors) {
  const value = parseInt(encoding, 16) >>> 0;
  const at = parseInt(pc, 16);
  const insn = encoding.length === 8 && !wide ? D.decodeArm(value, at) : wide ? D.decodeThumb(value >>> 16, value & 0xffff, at) : D.decodeThumb(value, 0, at);
  const got = D.formatInsn(insn);
  if (got !== text && wrong++ < 20) check(`${encoding} at ${pc}`, got, text);
}
check(`all ${vectors.length} vectors match llvm-objdump`, wrong, 0);
check('vectors cover A32, 16- and 32-bit T32', [vectors.some((v) => v[0].length === 8 && !v[3]), vectors.some((v) => v[0].length === 4), vectors.some((v) => v[3])], [true, true, true]);

const t16 = (hw, pc = 0x1000, it = -1) => D.decodeThumb(hw, 0, pc, it);
const t32 = (hw1, hw2, pc = 0x1000, it = -1) => D.decodeThumb(hw1, hw2, pc, it);
const a32 = (word, pc = 0x1000) => D.decodeArm(word, pc);

// Sizes.
check('sizes', [t16(0x4770).size, t32(0xf852, 0x3b04).size, a32(0xe12fff1e).size], [2, 4, 4]);
check('wide halfwords', [D.isWide(0xe800), D.isWide(0xf000), D.isWide(0xdfff)], [true, true, false]);

// Branches: targets, conditions, and the instruction set at the other end.
const bhi = t16(0xd804, 0x7a2);
check('Thumb b<cond>', [D.formatInsn(bhi), bhi.target, bhi.cond, !!(bhi.f & F.COND)], ['bhi 0x7ae', 0x7ae, 'hi', true]);
const blx = t32(0xf000, 0xec34, 0x7c4);
check('blx from Thumb goes to A32, word-aligned', [blx.target, blx.thumb, !!(blx.f & F.CALL)], [0x1030, false, true]);
check('A32 b', a32(0xeafffff8, 0x738).target, 0x720);
check('A32 bl stays in A32', a32(0xebfffffe, 0x1030).thumb, false);
check('cbz', [t16(0xb108, 0x100).target, !!(t16(0xb108).f & F.COND)], [0x106, true]);
const ret = t16(0xbd80);
check('pop {…, pc} returns', [!!(ret.f & F.RET), !!(ret.f & F.LOAD)], [true, true]);
check('bx lr returns', !!(t16(0x4770).f & F.RET), true);
check('popeq', [D.formatInsn(a32(0x08bd8800)), a32(0x08bd8800).cond], ['popeq {r11, pc}', 'eq']);

// Literals: the address a PC-relative load reads.
check('Thumb literal: Align(pc + 4, 4) + imm', t16(0x4904, 0x7a4).target, 0x7b8);
check('A32 literal: pc + 8 + imm', a32(0xe59f0008, 0x70c).target, 0x71c);
check('literal size', t16(0x4904).bytes, 4);

// IT blocks: the IT names the conditions, the instructions in it print and carry them.
const itt = t16(0xbfbc, 0x782);
check('itt lt', [D.formatInsn(itt), itt.it], ['itt lt', [11, 11]]);
check('movs loses its s inside IT', D.formatInsn(t16(0x2000, 0x784, 11)), 'movlt r0, #0x0');
check('conditional return', [D.formatInsn(t16(0x4770, 0x786, 11)), t16(0x4770, 0x786, 11).cond], ['bxlt lr', 'lt']);
check('itte', D.itConditions(0, 0b0110), [0, 0, 1]);
check('it suffix', D.itSuffix(0, 0b0110), 'te');
check('nested IT keeps the outer rest', D.itAfter([1, 1], itt, 0xbfbc), [11, 11, 1]);
check('an undecodable instruction takes no IT slot', D.itAfter([1, 1], D.unknown(0xffffffff, 4, true), 0xffffffff), [1, 1]);
check('a decoded one does', D.itAfter([1, 1], t16(0x4770, 0x786, 1), 0x4770), [1]);

// Table branches, NEON, traps, unknown words.
check('tbh', D.formatInsn(t32(0xe8df, 0xf012)), 'tbh [pc, r2, lsl #1]');
check('vld1 with writeback', [D.formatInsn(t32(0xf96e, 0x2a8d)), !!(t32(0xf96e, 0x2a8d).f & F.LOAD)], ['vld1.32 {d18, d19}, [lr]!', true]);
check('vcvt', D.formatInsn(t32(0xeef8, 0x0bc0)), 'vcvt.f64.s32 d16, s0');
check('trap', [D.formatInsn(t16(0xdefe)), !!(t16(0xdefe).f & F.TRAP)], ['trap', true]);
check('A32 trap', D.formatInsn(a32(0xe7ffdefe)), 'trap');
check('unknown A32', [a32(0xffffffff).m, !!(a32(0xffffffff).f & F.UNKNOWN)], ['.inst', true]);

done('arm32');
