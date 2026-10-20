/**
 * The decoder against fixed vectors: thousands of words with the exact text
 * llvm-objdump prints for them (tests/fixtures/decode-vectors.json, made by
 * `node tools/verify-decoder.mjs … --vectors`), and the structure behind a
 * few: branch targets, flags, memory sizes, the operands the HLA64 view reads.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const { check, done } = checker();
const { decode, formatInsn, F } = await load('core/arm64/decode', 'core/arm64/types');

const { vectors } = JSON.parse(readFileSync(join(root, 'tests', 'fixtures', 'decode-vectors.json'), 'utf8'));
let wrong = 0;
for (const [word, pc, text] of vectors) {
  const got = formatInsn(decode(parseInt(word, 16), parseInt(pc, 16)));
  if (got !== text) {
    if (wrong++ < 20) check(`${word} at ${pc}`, got, text);
  }
}
check(`all ${vectors.length} vectors match llvm-objdump`, wrong, 0);

const at = (word, pc = 0x100000000) => decode(word, pc);

// Branches carry their targets and kinds.
const bne = at(0x54000401, 0x100000f70);
check('b.ne target', bne.target, 0x100000ff0);
check('b.ne is a conditional branch reading flags', [!!(bne.f & F.BRANCH), !!(bne.f & F.COND), !!(bne.f & F.READS_FLAGS), bne.cond], [true, true, true, 'ne']);
const cbz = at(0xb4ffff88, 0x100000fb0);
check('cbz backwards', cbz.target, 0x100000fa0);
check('bl is a call', !!(at(0x94000000).f & F.CALL), true);
check('blr is an indirect call', at(0xd63f0100).f & (F.CALL | F.INDIRECT), F.CALL | F.INDIRECT);
check('ret', [at(0xd65f03c0).m, !!(at(0xd65f03c0).f & F.RET)], ['ret', true]);
check('brk traps', !!(at(0xd4200020).f & F.TRAP), true);
const adrp = at(0xb0004161, 0x10000724c);
check('adrp page', adrp.target, 0x100834000);

// Memory: sizes, signedness, addressing modes.
const ldrb = at(0x39401c08);
check('ldrb size and offset', [ldrb.size, ldrb.signed, ldrb.ops[1]], [1, undefined, { k: 'mem', base: 'x0', off: 7, mode: 'off' }]);
check('ldrsw is signed', [at(0xb9800016).size, at(0xb9800016).signed], [4, true]);
check('post-index', at(0xf840867c).ops[1], { k: 'mem', base: 'x19', off: 8, mode: 'post' });
check('pre-index pair', at(0xa9bf7bfd).ops[2], { k: 'mem', base: 'sp', off: -16, mode: 'pre' });
check('ldaddl is atomic', !!(at(0xf8690108).f & F.ATOMIC), true);
check('casl', formatInsn(at(0xc8a8fe7f)), 'casl x8, xzr, [x19]');

// Flags.
check('cmp sets flags', !!(at(0xf100051f).f & F.SETS_FLAGS), true);
check('cset reads flags with the alias condition', [at(0x1a9f07e0).m, at(0x1a9f07e0).cond], ['cset', 'ne']);
check('ccmp', formatInsn(at(0xfa519822)), 'ccmp x1, #0x11, #0x2, ls');

// Immediates.
check('mov of a negative 32-bit value', formatInsn(at(0x52b00008)), 'mov w8, #-0x80000000');
// DecodeBitMasks itself: the bitmask tests in crates/core/src/arm64/encode.rs.
check('fmov immediate', formatInsn(at(0x1e6e1001)), 'fmov d1, #1.00000000');

// The base-instruction extensions of 2023–2025: compare-and-branch, PAuth_LR, GCS, MTE, LRCPC3, LSUI, LSFE, MOPS, TEV.
const cbgt = at(0x7507bfaa);
check('cbgt is a conditional branch with a target', [formatInsn(cbgt), cbgt.target, cbgt.f & (F.BRANCH | F.COND | F.READS_FLAGS), cbgt.cond], ['cbgt w10, #0xf, 0xfffffff4', 0xfffffff4, F.BRANCH | F.COND, 'gt']);
const retaasppc = at(0x5504d07f);
check('retaasppc returns; its label is no branch target', [formatInsn(retaasppc), !!(retaasppc.f & F.RET), retaasppc.target], ['retaasppc 0xffff65f4', true, undefined]);
check('pacm', formatInsn(at(0xd50324ff)), 'pacm');
check('gcspopm', formatInsn(at(0xd52b7728)), 'gcspopm x8');
check('gcspushm', formatInsn(at(0xd50b771e)), 'gcspushm x30');
check('GCSPR_EL0', formatInsn(at(0xd53b2538)), 'mrs x24, GCSPR_EL0');
check('stg is a store', [formatInsn(at(0xd9200908)), !!(at(0xd9200908).f & F.STORE)], ['stg x8, [x8]', true]);
check('ldapr post-index, in decimal', [formatInsn(at(0x99c00a5b)), at(0x99c00a5b).ops[1].mode], ['ldapr w27, [x18], #4', 'post']);
check('stfaddl is atomic', [formatInsn(at(0xbc6e803f)), !!(at(0xbc6e803f).f & F.ATOMIC)], ['stfaddl s14, [x1]', true]);
check('ldtp of Q registers', formatInsn(at(0xed627360)), 'ldtp q0, q28, [x27, #-0x3c0]');
check('cpyfp', formatInsn(at(0x1906067a)), 'cpyfp [x26]!, [x6]!, x19!');
check('tenter', formatInsn(at(0xd4e20ca0)), 'tenter #0x65, nb');

// What is not an instruction.
check('udf for zero', formatInsn(at(0)), 'udf #0x0');
check('unknown words', at(0xffffffff).m, '.inst');
check('unknown flag', !!(at(0xffffffff).f & F.UNKNOWN), true);

done('decode');
