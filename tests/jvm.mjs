/**
 * Java bytecode: the JVM decoder against javap's text of tests/fixtures/jvm/hello.jar
 * (hello.javap, made by its build.sh), every instruction of every method; the class file reader
 * and the analysis on the same JAR; its HLA64 view; and the rules of javap's that the JDK and
 * the IDEs' JARs taught, on small cases — quoting names, Java's way of writing floating point.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';
import { codeBlocks, javapClasses, normal } from '../tools/javap-text.mjs';

const { check, done } = checker();
const C = await load('core/zip', 'core/jvm/classfile', 'core/jvm/opcodes', 'core/jvm/decode', 'core/jvm/program', 'core/jvm/hla', 'core/rows', 'core/catalog');
const dir = join(root, 'tests', 'fixtures', 'jvm');
const bytes = new Uint8Array(readFileSync(join(dir, 'hello.jar')));
const plain = (text) => text.replace(/\u0001[a-z]-?\d+\u0002/g, '').replace(/\u0003/g, '');

/* ---------------- the decoder, against javap ---------------- */

// javap printed the classes in the order of the JAR's entries.
const entries = C.zipEntries(bytes).filter((e) => e.name.endsWith('.class'));
const reference = javapClasses(readFileSync(join(dir, 'hello.javap'), 'utf8'));
check('javap printed every class', reference.length, entries.length);
const insn = new C.JvmInsn();
let total = 0;
let wrong = 0;
for (let k = 0; k < entries.length; k++) {
  const cf = new C.ClassFile(await C.zipRead(bytes, entries[k]), entries[k].name);
  const blocks = codeBlocks(reference[k] ?? []);
  const methods = cf.methods.filter((m) => m.code);
  if (blocks.length !== methods.length) check(`${cf.name}: methods with code`, methods.length, blocks.length);
  methods.forEach((method, m) => {
    const ours = new Map();
    const code = method.code;
    for (let pos = code.offset; pos < code.offset + code.length; pos += insn.len) {
      C.decodeAt(cf.bytes, code.offset, pos, code.offset + code.length, insn);
      // javap's output is UTF-8, where a lone surrogate becomes `?`.
      ours.set(insn.at, normal(C.insnText(cf, insn).replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, '?')));
    }
    for (const [pc, want] of blocks[m] ?? []) {
      total++;
      if (ours.get(pc) !== normal(want) && wrong++ < 20) check(`${cf.name}.${method.name} @${pc}`, ours.get(pc), normal(want));
    }
    if (ours.size !== (blocks[m] ?? []).length) check(`${cf.name}.${method.name}: instruction count`, ours.size, (blocks[m] ?? []).length);
  });
}
check(`all ${total} instructions match javap`, wrong, 0);

/* ---------------- constants as javap writes them ---------------- */

check('Double.toString', [4.9e-324, 1e23, 1e7, 9999999.0, 0.001, 1e-3 / 2, 123456789.125, -0.0, 100, 0.1, 2.5e-5].map(C.javaDouble), ['4.9E-324', '1.0E23', '1.0E7', '9999999.0', '0.001', '5.0E-4', '1.23456789125E8', '-0.0', '100.0', '0.1', '2.5E-5']);
check('Float.toString', [Math.fround(1.4e-45), Math.fround(0.1), Math.fround(3.4e38), Math.fround(1e-7), 1.28515625, Math.fround(1e7), NaN, -Infinity].map(C.javaFloat), ['1.4E-45', '0.1', '3.4E38', '1.0E-7', '1.2851562', '1.0E7', 'NaN', '-Infinity']);
check('names javap quotes', ['java/lang/String', '<init>', '[I', 'with space', 'имя', 'emoji😀', 'a//b', '1st', 'kebab-case', ''].map(C.checkName), ['java/lang/String', '"<init>"', '"[I"', '"with space"', 'имя', '"emoji😀"', '"a//b"', '"1st"', '"kebab-case"', '""']);
check('string escapes', C.escapeString('tab\t"q"\'s\\ \u0001\u0085 é'), 'tab\\t\\"q\\"\\\'s\\\\ \\u0001\\u0085 é');
check('descriptors', [C.methodTypes('([Ljava/lang/String;IJ)V'), C.fieldType('[[D'), C.descriptorKinds('(IJLjava/lang/Object;[DF)Z')], [{ params: ['java.lang.String[]', 'int', 'long'], ret: 'void' }, 'double[][]', { params: 'ilaaf', ret: 'i' }]);
check('a universal Mach-O file is not a class file', C.isClassFile(Uint8Array.of(0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2, 0, 0)), false);

/* ---------------- the archive and the analysis ---------------- */

const { classes, container } = await C.readClasses(bytes);
const p = await C.analyzeJvm(classes, container);
const fn = (name) => p.functions.find((f) => f.name === name);
check('classes, sorted', classes.map((c) => c.name).slice(0, 4), ['hello/Hello', 'hello/Hello$Kind', 'hello/Hello$Point', 'hello/More']);
check('the manifest', container.manifest.get('Main-Class'), 'hello.Hello');
check('arch and platform', [p.archLabel(), p.platformLabel()], ['JVM', 'Java 25']);
check('the entry point', [C.entryOf(p)?.name, fn('hello.Hello::main')?.kind], ['hello.Hello::main', 'entry']);
check('every method with code is a function', p.functions.length, classes.reduce((n, c) => n + c.methods.filter((m) => m.code).length, 0));
check('a declaration', fn('hello.Hello::sum')?.full, 'static long hello.Hello.sum(int[], int)');
check('callers', p.callers.get(fn('hello.Hello::sum').addr)?.length, 1);
const println = p.imported.find((m) => m.name === 'java.io.PrintStream::println' && m.descriptor === '(Ljava/lang/String;)V');
check('a member of another class', [println?.package, println?.kind, println?.full], ['java.io', 'import', 'void java.io.PrintStream.println(java.lang.String)']);
check('calls to it are counted', (p.callers.get(println.addr)?.length ?? 0) >= 4, true);
check('a method of a class here is not an import', p.imported.some((m) => m.owner.startsWith('hello/') && m.member === 'sum'), false);
check('a lambda body is taken', (p.dataRefs.get(fn('hello.Hello::lambda$main$0').addr)?.length ?? 0) >= 1, true);
const usage = p.strings.find((s) => s.text === 'usage: hello [numbers...]');
check('strings are counted once, used where ldc loads them', [!!usage, p.dataRefs.get(usage?.addr)?.length], [true, 1]);
const sum = fn('hello.Hello::sum');
const at = (f, m) => { for (let i = f.first; i < f.first + f.count; i++) if (p.insn(i).m === m) return i; return -1; };
const branch = at(sum, 'if_icmpge');
check('if_icmpge goes to L25', [p.insn(branch).m, p.labelName(p.addrOf(p.branchTargets(branch)[0]))], ['if_icmpge', 'L25']);
const main = fn('hello.Hello::main');
const regions = [...p.regions].filter(([index]) => index >= main.first && index < main.first + main.count).map(([, list]) => list.map((r) => r.part).join());
check('protected ranges and handlers start at labels', [regions[0], regions.join().split('handler').length - 1], ['try,try', 4]);
const kindOf = fn('hello.Hello::kindOf');
check('a switch goes to its cases and its default', p.branchTargets(at(kindOf, 'tableswitch')).length, 4);
check('ranges are classes', p.ranges.map((r) => r.name).slice(0, 3), ['class hello.Hello', 'enum hello.Hello$Kind', 'record hello.Hello$Point']);
check('rows', C.buildRows(p, 'asm').count > p.totalInstructions, true);
check('no instruction left undecoded', p.counts.find((c) => c.mnemonic === '.byte'), undefined);
check('every mnemonic has an entry', p.counts.filter((c) => !C.JVM_CATALOGUE.lookup(c.mnemonic)).map((c) => c.mnemonic), []);
check('wide forms', ['iload_w', 'istore_w', 'iinc_w', 'astore_w', 'ret_w', 'jsr', 'jsr_w', 'goto_w'].filter((m) => !p.counts.some((c) => c.mnemonic === m)), []);

/* ---------------- HLA64 ---------------- */

/** The HLA64 lines of a method, each with the pc it starts at. */
function lines(name) {
  const f = fn(name);
  const out = [];
  for (let i = f.first; i < f.first + f.count; ) {
    let last = i;
    while (p.flags[last] & 2 && last + 1 < f.first + f.count) last++;
    const line = C.liftGroup(p, i, last);
    out.push(line ? plain(line.text) : null);
    i = last + 1;
  }
  return out;
}
check('a loop', lines('hello.Hello::sum'), ['total = 0', 'i = 0', 'if i >= count { goto L25 }', 'total += i64(values[i])', 'i += 1', 'goto L5', 'return total']);
const mainLines = lines('hello.Hello::main');
for (const want of [
  'if len(args) <= 0 { goto L25 }',
  'System::out.println("usage: hello [numbers...]")',
  'values = new int[8] { 1, 2, 3, 4, 5, 6, 7, 8 }',
  'sum = Hello::sum(values, len(values))',
  'avg = f64(sum) / f64(len(values))',
  'System::out.println(concat("Hello, world! sum=", sum, " avg=", String::format("%.2f", new Object[1] { Double::valueOf(avg) }), " kind=", Hello::kindOf(sum)))',
  'p = new Point(3, 4)',
  'twice = lambda<IntUnaryOperator, Hello::`lambda$main$0`>()',
  'list = new ArrayList(List::of("pear", "apple", "fig"))',
]) check(`main: ${want}`, mainLines.includes(want), true);
// A NaN would make `value < 1.5` true where dcmpg; ifge goes on: the comparison stays.
check('floats compared where a NaN decides', lines('hello.Hello::classify').slice(0, 2), ['if dcmpg(value, 1.5) >= 0 { goto L12 }', 'return Kind::SMALL']);
check('a value made before a label is not returned as nothing', lines('hello.Hello::kindOf').at(-1), null);
check('a field incremented', lines('hello.More::fields').slice(0, 3), ['this.count += 1', 'this.total += i64(l1)', 'this.count *= 2']);
check('a long array element incremented (dup2)', lines('hello.More::arrays').includes('l8[1] += 1'), true);
check('a result thrown away', lines('hello.More::discard'), ['System::nanoTime()', 'System::currentTimeMillis()', 'Math::max(1, 2)', '"x".length()', 'return']);
check('a constructor calls its super', lines('hello.Hello::<init>'), ['Object::`<init>`(this)', 'return']);
check('long comparisons joined', lines('hello.More::compares').slice(1, 2), ['if l1 <= 0 { goto L12 }']);
check('subroutines stay instructions', lines('hello.Old::subroutines').slice(0, 2), [null, null]);
// Every run the analysis groups is one line here: the two agree.
let failed = 0;
for (let i = 0; i < p.totalInstructions; ) {
  let last = i;
  while (p.flags[last] & 2 && last + 1 < p.totalInstructions) last++;
  if (last > i && !C.liftGroup(p, i, last)) failed++;
  i = last + 1;
}
check('every group the analysis makes is lifted', failed, 0);

done('jvm');
