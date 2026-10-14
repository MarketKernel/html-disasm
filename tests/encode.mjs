/**
 * The assembler against the decoder: every vector line of an instruction it
 * covers (tests/fixtures/decode-vectors.json, as llvm-objdump prints them)
 * must assemble to a word that decodes to the same text; so must random
 * words of those instructions, decoded and printed first. Then the other
 * spellings people type — aliases, decimal, names — and the errors.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const { check, done } = checker();
const { assemble, encodeBitMask, decode, decodeBitMask, formatInsn } = await load('core/arm64/encode', 'core/arm64/decode', 'core/arm64/types');

/** The mnemonics the assembler takes, as the decoder prints them (b.cond and bc.cond apart). */
const COVERED = new Set(
  `nop yield wfe wfi sev sevl hint b bl br blr ret cbz cbnz tbz tbnz brk udf svc hvc smc hlt dmb dsb isb clrex sb ssbb pssbb dfb
  xpaclri pacia1716 pacib1716 autia1716 autib1716 esb psb tsb gcsb csdb clrbhb paciaz paciasp pacibz pacibsp autiaz autiasp autibz autibsp bti pacm chkfeat dgh
  mov movz movn movk add adds sub subs cmp cmn neg negs adc adcs sbc sbcs ngc ngcs
  and orr eor ands bic orn eon bics tst mvn lsl lsr asr ror extr
  mul madd msub mneg smull umull smnegl umnegl smaddl umaddl smsubl umsubl smulh umulh sdiv udiv
  csel csinc csinv csneg cset csetm cinc cinv cneg ccmp ccmn
  sxtb sxth sxtw uxtb uxth ubfx sbfx ubfiz sbfiz bfi bfxil clz cls rbit rev rev16 rev32 adr adrp
  ldr str ldrb strb ldrh strh ldrsb ldrsh ldrsw ldur stur ldurb sturb ldurh sturh ldursb ldursh ldursw
  ldtr sttr ldtrb sttrb ldtrh sttrh ldtrsb ldtrsh ldtrsw prfm prfum
  ldp stp ldpsw ldnp stnp ldxr ldaxr stxr stlxr ldar stlr ldlar stllr ldxrb ldxrh ldaxrb ldaxrh stxrb stxrh stlxrb stlxrh
  ldarb ldarh stlrb stlrh ldlarb ldlarh stllrb stllrh ldxp ldaxp stxp stlxp
  fmov fadd fsub fmul fdiv fnmul fmax fmin fmaxnm fminnm fneg fabs fsqrt fcmp fcmpe fcsel fccmp fccmpe fcvt
  frintn frintp frintm frintz frinta frintx frinti frint32z frint32x frint64z frint64x fmadd fmsub fnmadd fnmsub
  scvtf ucvtf fcvtzs fcvtzu fcvtns fcvtnu fcvtps fcvtpu fcvtms fcvtmu fcvtas fcvtau
  abs cnt ctz smax umax smin umin ldapr ldaprb ldaprh`.split(/\s+/),
);
// The LSE atomics, with every ordering and size.
for (const order of ['', 'a', 'l', 'al']) {
  for (const size of ['', 'b', 'h']) {
    for (const op of ['add', 'clr', 'eor', 'set', 'smax', 'smin', 'umax', 'umin']) {
      COVERED.add(`ld${op}${order}${size}`);
      if (!order.includes('a')) COVERED.add(`st${op}${order}${size}`);
    }
    COVERED.add(`swp${order}${size}`);
    COVERED.add(`cas${order}${size}`);
    if (!size) COVERED.add(`casp${order}`);
  }
}
// Vector registers, SVE and the SIMD forms of the scalar mnemonics are not assembled.
const vectorForm = (text) => /\bv\d+\.|\bz\d+|\bp\d+/.test(text);
const covered = (text) => {
  const m = text.split(' ')[0];
  return (COVERED.has(m) || /^bc?\.\w+$/.test(m)) && !vectorForm(text);
};

const hexWord = (word) => (word >>> 0).toString(16).padStart(8, '0');

/**
 * What Arm leaves unpredictable and LLVM's assembler refuses, read from the
 * text: ldp loading one register twice, a written-back base that is also
 * transferred, a store-exclusive status register that is also a source.
 */
const UNPREDICTABLE = 'Arm leaves the result of this combination of registers unpredictable.';
function unpredictable(text) {
  const m = text.split(' ')[0];
  const [before, after = ''] = text.slice(m.length + 1).split('[');
  const number = (name) => (/^[xw]zr$/.test(name) ? 31 : Number(/^[xwbhsdq](\d+)$/.exec(name)?.[1] ?? -1));
  const regs = before.split(',').map((name) => name.trim()).filter(Boolean).map(number);
  const base = after.startsWith('sp') ? 31 : number(/^x\d+/.exec(after)?.[0] ?? '');
  const general = /^[xw]/.test(before);
  if ((m === 'ldp' || m === 'ldpsw') && regs[0] === regs[1]) return true;
  if (/\]!|\], #/.test(text) && general && base !== 31 && regs.includes(base)) return true;
  if (/^st(l?)x[rp]/.test(m)) return regs.slice(1).includes(regs[0]) || (regs[0] === base && base !== 31);
  return false;
}

/** Assembles `text` at `pc` and says what went wrong, or null; 'other' for another word that prints the same. */
function roundTrip(text, pc, word) {
  const out = assemble(text, pc);
  if (out.error === UNPREDICTABLE && unpredictable(text)) return 'unpredictable';
  if (out.error) return `${text}: ${out.error}`;
  if (unpredictable(text)) return `${text}: assembled, though unpredictable`;
  const back = formatInsn(decode(out.word, pc));
  if (back !== text) return `${text}: assembled ${hexWord(out.word)}, which decodes to ${back}`;
  return out.word === word ? null : 'other';
}

// Every covered vector.
const { vectors } = JSON.parse(readFileSync(join(root, 'tests', 'fixtures', 'decode-vectors.json'), 'utf8'));
let total = 0;
let exact = 0;
let refused = 0;
const failures = [];
for (const [word, pc, text] of vectors) {
  if (!covered(text)) continue;
  total += 1;
  const problem = roundTrip(text, parseInt(pc, 16), parseInt(word, 16));
  if (problem === null) exact += 1;
  else if (problem === 'unpredictable') refused += 1;
  else if (problem !== 'other') failures.push(problem);
}
for (const problem of failures.slice(0, 30)) console.error(`  ${problem}`);
check(`all ${total} covered vectors assemble back`, failures.length, 0);
console.log(`vectors: ${total} of covered instructions, ${total - failures.length - refused} assemble back (${exact} to the very same word), ${refused} refused as unpredictable`);

// Random words: decoded, printed, assembled again.
let seed = 0x2545f491;
const random = () => {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return seed >>> 0;
};
let tried = 0;
let randomExact = 0;
let randomRefused = 0;
const randomFailures = [];
const pc = 0x100004000;
for (let i = 0; i < 400000; i++) {
  const word = random();
  const text = formatInsn(decode(word, pc));
  if (!covered(text)) continue;
  tried += 1;
  const problem = roundTrip(text, pc, word);
  if (problem === null) randomExact += 1;
  else if (problem === 'unpredictable') randomRefused += 1;
  else if (problem !== 'other') randomFailures.push(`${hexWord(word)} ${problem}`);
}
for (const problem of randomFailures.slice(0, 30)) console.error(`  ${problem}`);
check(`all ${tried} random covered words assemble back`, randomFailures.length, 0);
console.log(`random: ${tried} covered words, ${tried - randomFailures.length - randomRefused} assemble back (${randomExact} to the very same word), ${randomRefused} refused as unpredictable`);

// Other spellings, each assembled by clang (Xcode's, for aarch64-linux-gnu with the extensions on) to
// the word beside it: decimal and negative immediates, movz for mov, cs for hs, ldr where only ldur
// holds the offset, the zero-register forms the decoder prints as aliases.
const CLANG = `
d2800020 mov x0, #1
12800000 mov w0, #-1
12800000 mov w0, #0xffffffff
92800000 mov x0, #-1
d2a00020 mov x0, #0x10000
b2103fe0 mov x0, #0xffff0000ffff0000
52bfffe0 mov w0, #0xffff0000
b200f3e0 mov x0, #0x5555555555555555
9100001f mov sp, x0
910003e0 mov x0, sp
aa0103e0 mov x0, x1
2a0103e0 mov w0, w1
b2401fff mov sp, #0xff
d2a00020 movz x0, #1, lsl #16
52800000 movz w0, #0
12800000 movn w0, #0
92c24680 movn x0, #0x1234, lsl #32
72a24680 movk w0, #0x1234, lsl #16
f2ffffe0 movk x0, #0xffff, lsl #48
d1002020 add x0, x1, #-8
91400420 add x0, x1, #0x1000
91400420 add x0, x1, #1, lsl #12
91000020 add x0, x1, #0
9100003f add sp, x1, #0
d10103ff sub sp, sp, #0x40
b100041f cmp x0, #-1
31000c1f cmp w0, #-3
b140041f cmn x0, #4096
f1000420 adds x0, x1, #-1
713ffc20 subs w0, w1, #0xfff
8b2163e0 add x0, sp, x1
8b216be0 add x0, sp, x1, lsl #2
8b2163ff add sp, sp, x1
8b224820 add x0, x1, w2, uxtw #2
8b22c020 add x0, x1, w2, sxtw
0b220420 add w0, w1, w2, uxtb #1
8b226c20 add x0, x1, x2, uxtx #3
0b2143e0 add w0, wsp, w1
eb21401f cmp x0, w1, uxtw
eb2163ff cmp sp, x1
eb01001f subs xzr, x0, x1
cb0103e0 sub x0, xzr, x1
cb821420 sub x0, x1, x2, asr #5
2b027c20 adds w0, w1, w2, lsl #31
cb010fe0 neg x0, x1, lsl #3
6b0103e0 negs w0, w1
9a020020 adc x0, x1, x2
7a020020 sbcs w0, w1, w2
da0103e0 ngc x0, x1
92401c20 and x0, x1, #0xff
121f7820 and w0, w1, #-2
927c0c3f and sp, x1, #0xf0
9278dc20 bic x0, x1, #0xff
aa0103e0 orr x0, xzr, x1
aa010be0 orr x0, xzr, x1, lsl #2
aa2103e0 orn x0, xzr, x1
2a210fe0 mvn w0, w1, lsl #3
cac2fc20 eor x0, x1, x2, ror #63
6a220020 bics w0, w1, w2
ca220020 eon x0, x1, x2
f27d001f tst x0, #0x8
6a41081f tst w0, w1, lsr #2
f240001f ands xzr, x0, #1
d37df020 lsl x0, x1, #3
53010020 lsl w0, w1, #31
d340fc20 lsl x0, x1, #0
d37ffc20 lsr x0, x1, #63
13007c20 asr w0, w1, #0
93c11c20 ror x0, x1, #7
1ac22c20 ror w0, w1, w2
9ac22020 lsl x0, x1, x2
9ac22020 lslv x0, x1, x2
1ac22820 asrv w0, w1, w2
53001c20 ubfx w0, w1, #0, #8
d343fc20 ubfx x0, x1, #3, #61
d340fc20 ubfx x0, x1, #0, #64
d37df020 ubfiz x0, x1, #3, #61
93407c20 sbfx x0, x1, #0, #32
d37df020 ubfm x0, x1, #61, #60
13001c20 sbfm w0, w1, #0, #7
b3431020 bfm x0, x1, #3, #4
b3783c20 bfi x0, x1, #8, #16
33041c20 bfxil w0, w1, #4, #4
131f7820 sbfiz w0, w1, #1, #31
93401c20 sxtb x0, w1
13003c20 sxth w0, w1
93407c20 sxtw x0, w1
53001c20 uxtb w0, w1
53003c20 uxth w0, w1
93c11420 extr x0, x1, x1, #5
13827c20 extr w0, w1, w2, #31
1a9f37e0 cset w0, cs
da9f23e0 csetm x0, cc
9a812420 cinc x0, x1, lo
da81d020 cinv x0, x1, gt
5a815420 cneg w0, w1, mi
9a9f17e0 csinc x0, xzr, xzr, ne
9a810420 csinc x0, x1, x1, eq
5a9fe3e0 csinv w0, wzr, wzr, al
5a810420 csneg w0, w1, w1, eq
9a822020 csel x0, x1, x2, hs
fa451804 ccmp x0, #5, #4, ne
3a41e000 ccmn w0, w1, #0, al
9b027c20 madd x0, x1, x2, xzr
9b020c20 madd x0, x1, x2, x3
1b028c20 msub w0, w1, w2, w3
9b02fc20 mneg x0, x1, x2
1b027c20 mul w0, w1, w2
9b227c20 smaddl x0, w1, w2, xzr
9b220c20 smaddl x0, w1, w2, x3
9ba27c20 umull x0, w1, w2
9ba2fc20 umnegl x0, w1, w2
9b427c20 smulh x0, x1, x2
9bc27c20 umulh x0, x1, x2
1ac20820 udiv w0, w1, w2
9ac20c20 sdiv x0, x1, x2
dac00c20 rev x0, x1
5ac00820 rev w0, w1
dac00820 rev32 x0, x1
5ac00420 rev16 w0, w1
dac01020 clz x0, x1
5ac01420 cls w0, w1
5ac00020 rbit w0, w1
f9400020 ldr x0, [x1]
f9400420 ldr x0, [x1, #8]
f85f8020 ldr x0, [x1, #-8]
f8404020 ldr x0, [x1, #4]
b97ffc20 ldr w0, [x1, #0x3ffc]
f8408c20 ldr x0, [x1, #8]!
f85f0420 ldr x0, [x1], #-16
f8626820 ldr x0, [x1, x2]
f8627820 ldr x0, [x1, x2, lsl #3]
f8626820 ldr x0, [x1, x2, lsl #0]
b862d820 ldr w0, [x1, w2, sxtw #2]
b8624820 ldr w0, [x1, w2, uxtw]
b8624820 ldr w0, [x1, w2, uxtw #0]
f862e820 ldr x0, [x1, x2, sxtx]
38627820 ldrb w0, [x1, x2, lsl #0]
38626820 ldrb w0, [x1, x2]
38624820 ldrb w0, [x1, w2, uxtw]
39800420 ldrsb x0, [x1, #1]
38dffc20 ldrsb w0, [x1, #-1]!
78dfe020 ldrsh w0, [x1, #-2]
78a27820 ldrsh x0, [x1, x2, lsl #1]
b9800420 ldrsw x0, [x1, #4]
b8804420 ldrsw x0, [x1], #4
f8408020 ldur x0, [x1, #8]
f8500020 ldur x0, [x1, #-256]
b81fc3e0 stur w0, [sp, #-4]
380ff020 sturb w0, [x1, #255]
b8801020 ldursw x0, [x1, #1]
393ffc20 strb w0, [x1, #4095]
78002420 strh w0, [x1], #2
793fffff strh wzr, [sp, #8190]
f93ffc1f str xzr, [x0, #32760]
f8408820 ldtr x0, [x1, #8]
38000820 sttrb w0, [x1]
3dc00420 ldr q0, [x1, #16]
3ce27820 ldr q0, [x1, x2, lsl #4]
3c9f0c20 str q0, [x1, #-16]!
fc1f8fe0 str d0, [sp, #-8]!
bc403000 ldr s0, [x0, #3]
3d400400 ldr b0, [x0, #1]
7c617800 ldr h0, [x0, x1, lsl #1]
3cdff000 ldur q0, [x0, #-1]
fc0ff000 stur d0, [x0, #255]
a8c17bfd ldp x29, x30, [sp], #16
a9bf7bfd stp x29, x30, [sp, #-16]!
29010440 stp w0, w1, [x2, #8]
ad410400 ldp q0, q1, [x0, #32]
6d6007e0 ldp d0, d1, [sp, #-512]
2d1f8400 stp s0, s1, [x0, #252]
69408440 ldpsw x0, x1, [x2, #4]
a8400440 ldnp x0, x1, [x2]
ac200440 stnp q0, q1, [x2, #-1024]
f9800000 prfm pldl1keep, [x0]
f9800413 prfm pstl2strm, [x0, #8]
f8a1780c prfm plil3keep, [x0, x1, lsl #3]
f89f8001 prfum pldl1strm, [x0, #-8]
f980001f prfm #0x1f, [x0]
1e6e1000 fmov d0, #1.0
1e309000 fmov s0, #-2.5
1ee81000 fmov h0, #0.125
1e67f000 fmov d0, #31.0
9e6703e0 fmov d0, #0.0
1e2703e0 fmov s0, wzr
9e660020 fmov x0, d1
9e670020 fmov d0, x1
1e260020 fmov w0, s1
1ee70020 fmov h0, w1
9ee60020 fmov x0, h1
1e204020 fmov s0, s1
1e622820 fadd d0, d1, d2
1e223820 fsub s0, s1, s2
1ee20820 fmul h0, h1, h2
1e621820 fdiv d0, d1, d2
1e228820 fnmul s0, s1, s2
1e624820 fmax d0, d1, d2
1e227820 fminnm s0, s1, s2
1e614020 fneg d0, d1
1e20c020 fabs s0, s1
1e61c020 fsqrt d0, d1
1e65c020 frintz d0, d1
1e264020 frinta s0, s1
1e69c020 frint64x d0, d1
1e602008 fcmp d0, #0.0
1e212000 fcmp s0, s1
1e612010 fcmpe d0, d1
1ee02018 fcmpe h0, #0.0
1e622c20 fcsel d0, d1, d2, cs
1e211404 fccmp s0, s1, #4, ne
1e61e41f fccmpe d0, d1, #15, al
1e22c020 fcvt d0, s1
1ee24020 fcvt s0, h1
1e63c020 fcvt h0, d1
9e620020 scvtf d0, x1
1e230020 ucvtf s0, w1
1e42c020 scvtf d0, w1, #16
9ec30020 ucvtf h0, x1, #64
9e780020 fcvtzs x0, d1
1e19e020 fcvtzu w0, s1, #8
9ed8fc20 fcvtzs x0, h1, #1
5ea1b820 fcvtzs s0, s1
5f7dfc20 fcvtzs d0, d1, #3
7ef9b820 fcvtzu h0, h1
5f20e420 scvtf s0, s1, #32
7e61d820 ucvtf d0, d1
1e640020 fcvtas w0, d1
9e300020 fcvtms x0, s1
1ee10020 fcvtnu w0, h1
9e680020 fcvtps x0, d1
1f420c20 fmadd d0, d1, d2, d3
1f228c20 fnmsub s0, s1, s2, s3
d4001001 svc #0x80
d4200020 brk #1
d43e0000 brk #0xf000
00000000 udf #0
d4400000 hlt #0
d4000022 hvc #1
d503201f nop
d503203f yield
d503205f wfe
d503207f wfi
d503209f sev
d50320bf sevl
d503245f hint #34
d503201f hint #0
d5032c9f hint #100
d503245f bti c
d50324df bti jc
d503233f paciasp
d50323bf autiasp
d50320ff xpaclri
d5033fdf isb
d50333df isb #3
d5033bbf dmb ish
d50339bf dmb ishld
d50330bf dmb #0
d5033f9f dsb sy
d5033c9f dsb #12
d5033f5f clrex
d65f03c0 ret
d65f0020 ret x1
d65f03c0 ret x30
d61f0200 br x16
d63f0100 blr x8
c85f7c20 ldxr x0, [x1]
085f7c20 ldxrb w0, [x1]
485fffe0 ldaxrh w0, [sp]
c8037c20 stxr w3, x0, [x1]
c802fc20 stlxr w2, x0, [x1]
0802fc20 stlxrb w2, w0, [x1]
88dffc20 ldar w0, [x1]
08dffc20 ldarb w0, [x1]
c89fffe0 stlr x0, [sp]
489ffc20 stlrh w0, [x1]
c87f0440 ldxp x0, x1, [x2]
c8238440 stlxp w3, x0, x1, [x2]
f8200041 ldadd x0, x1, [x2]
b8e00041 ldaddal w0, w1, [x2]
38601041 ldclrlb w0, w1, [x2]
78a04041 ldsmaxah w0, w1, [x2]
b820003f stadd w0, [x1]
f860203f steorl x0, [x1]
3820003f ldaddb w0, wzr, [x1]
f8208041 swp x0, x1, [x2]
f8e08041 swpal x0, x1, [x2]
38208041 swpb w0, w1, [x2]
c8a07c41 cas x0, x1, [x2]
88e0fc41 casal w0, w1, [x2]
08e07c41 casab w0, w1, [x2]
48207c82 casp x0, x1, x2, x3, [x4]
0864ffe6 caspal w4, w5, w6, w7, [sp]
f8bfc020 ldapr x0, [x1]
38bfc020 ldaprb w0, [x1]
91c3ec20 smax x0, x1, #-5
11cf2020 umin w0, w1, #200
9ac26820 smin x0, x1, x2
dac02020 abs x0, x1
5ac01c20 cnt w0, w1
dac01820 ctz x0, x1
5ee28420 add d0, d1, d2
7ee28420 sub d0, d1, d2
7ee0b820 neg d0, d1
5ee0b820 abs d0, d1
1e760020 fcvtzs s0, d1
1e7c0020 scvtf d0, s1
9efd0020 ucvtf h0, d1
9eea0020 fcvtns d0, h1
d503309f ssbb
d503349f dsb #4
d5033c9f dsb #12
`;
for (const line of CLANG.trim().split('\n')) {
  const [, word, text] = /^(\w+) (.*)$/.exec(line);
  const out = assemble(text, 0x1000);
  check(text, out.error ?? hexWord(out.word), word);
}

// Branch and address targets: absolute addresses as llvm-objdump prints them, or names.
const at = 0x100003f00;
const names = { _main: 0x100003f40, _far: 0x108003f00, 'core::fmt::write<A, B>': 0x100000000, L100: 0x100003e00, _data: 0x100008123 };
const resolve = (name) => names[name];
const word = (text, pc = at) => {
  const out = assemble(text, pc, resolve);
  return out.error ?? hexWord(out.word);
};
check('b forward', word('b 0x100003f40'), '14000010');
check('b to a name', word('b _main'), '14000010');
check('bl backwards to a label', word('bl L100'), '97ffffc0');
check('a demangled name with commas', word('bl core::fmt::write<A, B>'), hexWord(0x94000000 | ((0x100000000 - at) / 4) & 0x3ffffff));
check('name plus offset', word('b _main+0x10'), '14000014');
check('the <symbol> llvm-objdump adds', word('bl 0x100003f40 <_main>'), '94000010');
check('b.cs is b.hs', word('b.cs _main'), '54000202');
check('cbz', word('cbz w0, 0x100003f40'), '34000200');
check('tbz on bit 3 of x0 is on w0', word('tbz x0, #3, _main'), '36180200');
check('tbnz on bit 40', word('tbnz x5, #40, _main'), 'b7400205');
check('adr', word('adr x1, _data'), hexWord(0x10000001 | ((0x100008123 - at) & 3) << 29 | (((0x100008123 - at) >> 2) & 0x7ffff) << 5));
check('adrp to the page of a name', word('adrp x8, _data'), formatAdrp(8, 0x100008000, at));
check('ldr literal', word('ldr x0, _main'), '58000200');
check('ldr literal of a q register', word('ldr q1, 0x100003f40'), '9c000201');
check('case and spacing', word('LDR  X0,[SP , # 16]'), word('ldr x0, [sp, #0x10]'));
check('comments', word('mov x0, #1 // one'), 'd2800020');
check('.inst', word('.inst 0xd503201f'), 'd503201f');

function formatAdrp(rd, page, pc) {
  const pages = (page - Math.floor(pc / 4096) * 4096) / 4096;
  return hexWord(0x90000000 | (pages & 3) << 29 | ((pages >> 2) & 0x7ffff) << 5 | rd);
}

// What cannot be assembled, and why.
check('empty', word('  '), 'Enter an instruction.');
check('unknown mnemonic', word('frobnicate x0'), 'This instruction cannot be assembled here; enter its encoding in hex instead.');
check('vector registers', word('add v0.4s, v1.4s, v2.4s'), 'This instruction cannot be assembled here; enter its encoding in hex instead.');
check('mixed widths', word('add x0, w1, x2'), 'The operands do not fit add.');
check('too far', word('b _far'), 'The target is too far: 134217728 bytes away.');
check('cbz too far', word('cbz x0, 0x100103f00'), 'The target is too far: 1048576 bytes away.');
check('misaligned target', word('b 0x100003f42'), 'The target is not a multiple of 4 bytes away.');
check('unknown name', word('bl _nowhere'), 'Unknown name: _nowhere.');
check('no bitmask', word('and x0, x1, #0x1234'), 'The immediate #0x1234 cannot be encoded here.');
check('mov needs two instructions', word('mov x0, #0x123456789'), 'The immediate #0x123456789 cannot be encoded here.');
check('add immediate too wide', word('add x0, x1, #0x1001'), 'The immediate #0x1001 cannot be encoded here.');
check('shift too far', word('lsl w0, w1, #32'), 'The immediate #0x20 cannot be encoded here.');
check('fmov immediate', word('fmov d0, #0.1'), 'The immediate #0.1 cannot be encoded here.');
check('offset out of range', word('ldr x0, [x1, #0x8000]'), 'The offset #0x8000 is out of range.');
check('offset misaligned', word('ldr x0, [x1, #0x1001]'), 'The offset #0x1001 is not a multiple of 8.');
check('pair offset misaligned', word('ldp x0, x1, [sp, #4]'), 'The offset #0x4 is not a multiple of 8.');
check('pre-index out of range', word('str x0, [sp, #-0x110]!'), 'The offset #-0x110 is out of range.');
check('unreadable', word('mov x0, #zz'), 'Cannot read “#zz”.');
check('cset al', word('cset w0, al'), 'The operands do not fit cset.');

// Bitmask immediates against the decoder's DecodeBitMasks, over every encoding.
let bitmaskWrong = 0;
for (const width of [32, 64]) {
  for (let n = 0; n < (width === 64 ? 2 : 1); n++) {
    for (let immr = 0; immr < 64; immr++) {
      for (let imms = 0; imms < 64; imms++) {
        const value = decodeBitMask(n, imms, immr, width);
        if (value === null || (width === 32 && (immr > 31 || imms > 31))) continue;
        const e = encodeBitMask(value, width);
        if (!e || decodeBitMask(e.n, e.imms, e.immr, width) !== value) bitmaskWrong += 1;
      }
    }
  }
}
check('every bitmask immediate encodes back', bitmaskWrong, 0);

// Fast enough to run on every keystroke.
const started = performance.now();
for (let i = 0; i < 10000; i++) assemble('stp x29, x30, [sp, #-0x10]!', at);
const each = (performance.now() - started) / 10000;
check('under 50 µs a line', each < 0.05, true);

done('assembler');
