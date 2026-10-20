/**
 * Java bytecode: every instruction of tests/fixtures/jvm/hello.jar as the page shows it, from the
 * core, against javap's text of it (hello.javap, made by its build.sh); the analysis on the same
 * JAR; its HLA64 view. The decoder's own cases (javap's ways of writing constants and names) are
 * in crates/core/tests/jvm.rs.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';
import { codeBlocks, javapClasses, normal } from '../tools/javap-text.mjs';

const { check, done } = checker();
const C = await load('core/archive', 'core/jvm/opcodes', 'core/jvm/program', 'core/rows', 'core/catalog');
const dir = join(root, 'tests', 'fixtures', 'jvm');
const bytes = new Uint8Array(readFileSync(join(dir, 'hello.jar')));
const plain = (text) => text.replace(/\u0001[a-z]-?\d+\u0002/g, '').replace(/\u0003/g, '');
const p = await C.analyzeJvm(bytes);

/* ---------------- the instructions, against javap ---------------- */

// javap printed the classes in the order of the JAR's entries; the program has them sorted.
const entries = C.zipNames(bytes).filter((name) => name.endsWith('.class')).map((name) => ({ name }));
const reference = javapClasses(readFileSync(join(dir, 'hello.javap'), 'utf8'));
check('javap printed every class', reference.length, entries.length);
check('the program has every class', p.classInfo.length, entries.length);
let total = 0;
let wrong = 0;
let blocksTotal = 0;
entries.forEach((entry, k) => {
  const cls = p.classInfo.findIndex((ci) => ci.path === entry.name);
  const blocks = codeBlocks(reference[k] ?? []);
  blocksTotal += blocks.length;
  const methods = p.bodies.map((body, f) => [body, f]).filter(([body]) => body.cls === cls).sort((a, b) => a[0].methodIndex - b[0].methodIndex);
  if (blocks.length !== methods.length) check(`${entry.name}: methods with code`, methods.length, blocks.length);
  methods.forEach(([, f], m) => {
    const fn = p.functions[f];
    const ours = new Map();
    for (let i = fn.first; i < fn.first + fn.count; i++) {
      const insn = p.insn(i);
      // javap's output is UTF-8, where a lone surrogate becomes `?`.
      ours.set(insn.at, normal(insn.text.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, '?')));
    }
    for (const [pc, want] of blocks[m] ?? []) {
      total++;
      if (ours.get(pc) !== normal(want) && wrong++ < 20) check(`${fn.name} @${pc}`, ours.get(pc), normal(want));
    }
    if (ours.size !== (blocks[m] ?? []).length) check(`${fn.name}: instruction count`, ours.size, (blocks[m] ?? []).length);
  });
});
check(`all ${total} instructions match javap`, wrong, 0);
check('a universal Mach-O file is not a class file', C.isClassFile(Uint8Array.of(0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2, 0, 0)), false);

/* ---------------- the archive and the analysis ---------------- */

const container = p.container;
const fn = (name) => p.functions.find((f) => f.name === name);
check('classes, sorted', p.classInfo.map((c) => c.name).slice(0, 4), ['hello/Hello', 'hello/Hello$Kind', 'hello/Hello$Point', 'hello/More']);
check('the manifest', container.manifest.get('Main-Class'), 'hello.Hello');
check('arch and platform', [p.archLabel(), p.platformLabel()], ['JVM', 'Java 25']);
check('the entry point', [C.entryOf(p)?.name, fn('hello.Hello::main')?.kind], ['hello.Hello::main', 'entry']);
check('every method with code is a function', p.functions.length, blocksTotal);
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
const regions = [];
for (let i = main.first; i < main.first + main.count; i++) if (p.regionsAt(i).length) regions.push(p.regionsAt(i).map((r) => r.part).join());
check('protected ranges and handlers start at labels', [regions[0], regions.join().split('handler').length - 1], ['try,try', 4]);
const kindOf = fn('hello.Hello::kindOf');
check('a switch goes to its cases and its default', p.branchTargets(at(kindOf, 'tableswitch')).length, 4);
check('ranges are classes', p.ranges.map((r) => r.name).slice(0, 3), ['class hello.Hello', 'enum hello.Hello$Kind', 'record hello.Hello$Point']);
check('rows', C.buildRows(p, 'asm').count > p.totalInstructions, true);
check('no instruction left undecoded', p.counts.find((c) => c.mnemonic === '.byte'), undefined);
check('every mnemonic has an entry', p.counts.filter((c) => !C.JVM_CATALOGUE.lookup(c.mnemonic)).map((c) => c.mnemonic), []);
check('wide forms', ['iload_w', 'istore_w', 'iinc_w', 'astore_w', 'ret_w', 'jsr', 'jsr_w', 'goto_w'].filter((m) => !p.counts.some((c) => c.mnemonic === m)), []);

/* ---------------- the cards ---------------- */

const index = (name) => p.functions.indexOf(fn(name));
const sumCard = p.method(index('hello.Hello::sum'));
check('a method card', [sumCard.modifiers, sumCard.descriptor, sumCard.class, sumCard.source, sumCard.firstLine, sumCard.maxStack, sumCard.maxLocals], ['static', '([II)J', 'hello.Hello', 'Hello.java', 18, 4, 5]);
check('its locals and header', [sumCard.locals[0], sumCard.params, sumCard.ret], [[4, 'i', 'int', 5, 20], [['values', 'int[]'], ['count', 'int']], 'long']);
check('handlers, a finally catching any', p.method(index('hello.Hello::main')).handlers.slice(0, 2), [
  { start: 133, end: 169, handler: 183, catch: 'java.lang.NumberFormatException' },
  { start: 133, end: 169, handler: 210, catch: 'any' },
]);
const hello = p.classView(0);
check('a class card', [hello.java, hello.modifiers, hello.kind, hello.extends, hello.source, hello.attributes[0]], ['hello.Hello', 'public', 'class', 'java.lang.Object', 'Hello.java', 'SourceFile']);
check('a field as Java declares it', p.field(0)?.decl, 'public static final hello.Hello$Kind hello.Hello$Kind.SMALL');
const refs = p.functionRefs(index('hello.Hello::main'));
check('what a method calls and loads', [refs.dynamic, refs.strings.slice(0, 2), refs.calls.every((pool) => p.callee(p.bodies[index('hello.Hello::main')].cls, pool))], [3, ['--help', 'usage: hello [numbers...]'], true]);
// A lone surrogate stays as it is: javap's terminal makes it `?`.
check('a string as javap writes it', p.escape('tab\t"q"\'s\\ \u0001\u0085 é\uD800'), 'tab\\t\\"q\\"\\\'s\\\\ \\u0001\\u0085 é\uD800');
const ldc = (() => { const f = fn('hello.Hello::main'); for (let i = f.first; i < f.first + f.count; i++) if (p.insn(i).string === 'usage: hello [numbers...]') return p.insn(i); })();
check('an instruction loading a string', [ldc?.m, ldc?.tag, ldc?.comment], ['ldc', C.CONSTANT.String, 'String usage: hello [numbers...]']);

/* ---------------- HLA64 ---------------- */

/** The HLA64 lines of a method, each with the pc it starts at. */
function lines(name) {
  const f = fn(name);
  const out = [];
  for (let i = f.first; i < f.first + f.count; ) {
    let last = i;
    while (p.flags[last] & 2 && last + 1 < f.first + f.count) last++;
    const line = p.hla(i, last);
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
  if (last > i && !p.hla(i, last)) failed++;
  i = last + 1;
}
check('every group the analysis makes is lifted', failed, 0);

done('jvm');
