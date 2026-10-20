/**
 * .NET: every instruction of tests/fixtures/dotnet/hello.dll as the page shows it, from the core,
 * against ildasm's text of it (hello.il, made by its build.sh); what the page reads of the
 * metadata and the analysis on the same assembly; its HLA64 view. ildasm's rules on small cases —
 * quoting names, breaking parameter lists at commas, floating-point constants, strings — are in
 * crates/core/tests/cil.rs.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';
import { referenceLines } from '../tools/ildasm-text.mjs';

const { check, done } = checker();
const C = await load('core/pe', 'core/cil/opcodes', 'core/cil/program', 'core/rows', 'core/catalog');
const dir = join(root, 'tests', 'fixtures', 'dotnet');
const bytes = new Uint8Array(readFileSync(join(dir, 'hello.dll')));

const pe = C.parsePe(bytes);
check('a .NET assembly', pe.clr, true);
const p = await C.analyzeCil(pe);
const fn = (name) => p.functions.find((f) => f.name === name);
const index = (name) => p.functions.indexOf(fn(name));

/* ---------------- the instructions, against ildasm ---------------- */

const expected = referenceLines(readFileSync(join(dir, 'hello.il'), 'utf8'));
const ours = new Map();
p.functions.forEach((f, k) => {
  const rva = p.method(k).rva;
  for (let i = f.first; i < f.first + f.count; i++) {
    const insn = p.insn(i);
    ours.set(`${rva}:${insn.at}`, insn.text);
  }
});
let wrong = 0;
for (const [key, want] of expected) {
  if (ours.get(key) !== want && wrong++ < 20) check(key, ours.get(key), want);
}
check(`all ${expected.size} instructions match ildasm`, [wrong, ours.size], [0, expected.size]);

/* ---------------- what the page reads ---------------- */

const assembly = p.assemblyInfo();
check('metadata version', assembly.runtime[0], 'v4.0.30319');
check('streams', assembly.streams.map(([name]) => name), ['#~', '#Strings', '#US', '#GUID', '#Blob']);
check('the assembly', [assembly.assembly?.[0], assembly.module[0]], ['hello', 'hello.dll']);
check('types', assembly.types.slice(0, 2).map(([name, kind]) => [name, kind]), [['Hello.Kind', 'enum'], ['Hello.Point', 'struct']]);
check('#US', p.strings.some((s) => s.text === '--help'), true);
const mainCard = p.method(index('Hello.Program::Main'));
check('a fat body with clauses', [mainCard.fat, mainCard.clauses.map((c) => c.kind)], [true, [0, 2]]);
check('a clause in ILAsm', mainCard.clauses[0].text.startsWith('.try IL_'), true);
check('a signature line', p.method(index('Hello.Program::Sum')).signature, 'static int64 (int32[] values, int32 count)');
check('an HLA64 header', [p.method(index('Hello.Program::Sum')).params, p.method(index('Hello.Program::Sum')).ret], [[['values', 'int32[]'], ['count', 'int32']], 'int64']);
const helpString = p.strings.find((s) => s.text === '--help');
const ldstr = (() => { const f = fn('Hello.Program::Main'); for (let i = f.first; i < f.first + f.count; i++) if (p.insn(i).a === helpString.addr) return p.insn(i); })();
check('an ldstr', [ldstr?.m, ldstr?.operand, ldstr?.tokenKind, ldstr?.plain], ['ldstr', '"--help"', '#US', true]);
check('a string as ILAsm writes it', p.stringText(helpString.addr), '"--help"');
const refs = p.functionRefs(index('Hello.Program::Main'));
check('what a method calls and loads', [refs.calls.length > 3, refs.strings.some(([, text]) => text === '--help')], [true, true]);
check('references', p.referencesInfo().assemblies.some(([name]) => name === 'System.Console'), true);

/* ---------------- the analysis ---------------- */

check('assembly and framework', [p.assemblyName, p.framework, p.platformLabel(), p.archLabel()], ['hello', '.NETCoreApp,Version=v10.0', '.NET 10.0', 'CIL']);
check('every method with a body is a function', p.functions.length, 59);
check('the entry point', C.entryOf(p)?.name, 'Hello.Program::Main');
check('Main is the entry, Sum private', [fn('Hello.Program::Main')?.kind, fn('Hello.Program::Sum')?.kind, fn('Hello.More.Edge::Constants')?.kind], ['entry', 'symbol', 'export']);
check('a generic method is named with its parameters', !!fn('Hello.Program::Largest<T>'), true);
check('full signature', fn('Hello.Program::Sum')?.full, 'int64 Hello.Program::Sum(int32[], int32)');
check('callers', p.callers.get(fn('Hello.Program::Sum').addr)?.length, 1);
const writeLine = p.imported.find((m) => m.name === 'System.Console::WriteLine' && m.full.endsWith('(string)'));
check('a member of another assembly', [writeLine?.assembly, writeLine?.kind, writeLine?.full], ['System.Console', 'import', 'void [System.Console]System.Console::WriteLine(string)']);
check('calls to it are counted', (p.callers.get(writeLine.addr)?.length ?? 0) >= 2, true);
check('a method of a generic class here is not an import', p.imported.some((m) => m.name.includes('Hello.More.Box')), false);
check('P/Invoke', p.pinvokes.map((x) => [x.name, x.library, x.entry]), [['Hello.More.Edge::Abs', 'libc', 'abs']]);
const help = p.strings.find((s) => s.text === '--help');
check('strings are #US tokens', [help && C.tokenTable(help.addr), help && p.dataRefs.get(help.addr)?.length], [0x70, 1]);
const main = fn('Hello.Program::Main');
const branch = main.first + 2;
check('brfalse.s goes to IL_001f', [p.insn(branch).m, p.labelName(p.addrOf(p.branchTargets(branch)[0]))], ['brfalse.s', 'IL_001f']);
const regions = [...p.regions.keys()].filter((i) => i >= main.first && i < main.first + main.count).map((i) => p.regionsAt(i).map((r) => `${r.part}:${r.clause.kind}`).join());
check('try blocks and handlers start at labels', regions, ['try:0,try:2', 'handler:0', 'handler:2']);
check('ranges are types', p.ranges.map((r) => r.name).slice(0, 2), ['.class Hello.Point', '.class Hello.Program']);
check('the switch has its targets', p.branchTargets(fn('Hello.More.Edge::Switch').first + 1).length, 7);
check('rows', C.buildRows(p, 'asm').count > p.totalInstructions, true);
check('no instruction left undecoded', p.counts.find((c) => c.mnemonic === '.byte'), undefined);
check('every mnemonic has an entry', p.counts.filter((c) => !C.CIL_CATALOGUE.lookup(c.mnemonic)).map((c) => c.mnemonic), []);

/* ---------------- HLA64 ---------------- */

const strip = (text) => text.replace(/\u0001[a-z]-?\d+\u0002/g, '').replace(/\u0003/g, '');
/** The HLA64 view of a method: each row's line, or `[raw]` and its instructions. */
const view = (name) => {
  const f = fn(name);
  const lines = [];
  for (let i = f.first; i < f.first + f.count; i++) {
    const first = i;
    while (p.flags[i] & 2 && i + 1 < f.first + f.count) i++;
    const line = p.hla(first, i);
    lines.push(line ? strip(line.text) : `[raw] ${Array.from({ length: i - first + 1 }, (_, k) => p.insn(first + k).m).join('; ')}`);
  }
  return lines;
};
check('hla: a loop', view('Hello.Program::Sum'), ['V_0 = i64(0)', 'V_1 = 0', 'goto IL_0012', 'V_0 += i64(values[V_1])', 'V_1 += 1', 'if V_1 < count { goto IL_0007 }', 'return V_0']);
check('hla: calls, strings, a branch on false', view('Hello.Program::Main').slice(0, 4), [
  'if len(args) == 0 { goto IL_001f }',
  'if String::op_Equality(args[0], "--help") == 0 { goto IL_001f }',
  'Console::WriteLine("usage: hello [numbers...]")',
  'return 0',
]);
check('hla: conversions and division', view('Hello.Program::Main').slice(10, 12), ['V_1 = Program::Sum(V_0, i32(len(V_0)))', 'V_2 = f64(V_1) / f64(i32(len(V_0)))']);
check('hla: a struct by its address', view('Hello.Program::CountAsync').slice(0, 3), ['(&V_0).`<>t__builder` = AsyncTaskMethodBuilder<int32>::Create()', '(&V_0).n = n', '(&V_0).`<>1__state` = -1']);
check('hla: a switch falls through', view('Hello.More.Edge::Switch')[0], 'switch n { case 0 { goto IL_0024 } case 1 { goto IL_0027 } case 2 { goto IL_002a } case 3 { goto IL_002d } case 4 { goto IL_0036 } case 5 { goto IL_0030 } case 6 { goto IL_0033 } }');
check('hla: pointers', view('Hello.More.Edge::Five'), ['i32[field] = value + object', 'i32[method] = i32[method] + 1', 'return a + b + c + d + value']);
check('hla: pinned arrays and typed memory', view('Hello.Program::Checksum').filter((l) => l.includes('u8[') || l.includes('nuint')), ['V_1 = nuint(0)', 'V_1 = nuint(&V_2[0])', 'V_0 = (V_0 << 1) ^ u8[V_1 + V_3]']);
check('hla: a volatile field stays instructions', view('Hello.More.Box`1::set_Value')[1], '[raw] ldarg.0');
check('hla: a dup of a value that is not a variable stays an instruction', view('Hello.Program::Main').some((l) => l.startsWith('[raw] dup')), true);
check('hla: comparisons of comparisons are parenthesized', view('Hello.Program::Main').at(-1), 'return (TaskAwaiter<int32>::GetResult(&V_10) > 0) == 0');
check('hla: float constants', view('Hello.More.Edge::Constants').slice(8, 16), ['V_7 = 1.0', 'V_8 = 0.1', 'V_9 = nan', 'V_10 = inf', 'V_11 = -0.0', 'V_12 = 3.4e+38', 'V_13 = 1e-7', 'V_14 = 2.0']);
// value < 1.5 is compiled to bge.un: between floats "greater or equal, or unordered", which no operator says.
check('hla: an unordered float branch stays instructions', view('Hello.Program::Classify')[0], '[raw] ldarg.0; ldc.r8; bge.un.s');
let errors = 0;
let lifted = 0;
let lines = 0;
for (const f of p.functions) {
  for (let i = f.first; i < f.first + f.count; i++) {
    const first = i;
    while (p.flags[i] & 2 && i + 1 < f.first + f.count) i++;
    lines++;
    try {
      if (p.hla(first, i)) lifted++;
    } catch {
      errors++;
    }
  }
}
check('hla: every row lifts or stays instructions', errors, 0);
check('hla: most rows read as HLA64', lifted / lines > 0.45, true);
// The kinds of types, float literals and short type names: the tests in crates/core/src/cil/hla.rs.

done('cil');
