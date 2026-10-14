/**
 * .NET: the CIL decoder against ildasm's text of tests/fixtures/dotnet/hello.dll
 * (hello.il, made by its build.sh), every instruction of every method; the
 * metadata reader and the analysis on the same assembly; its HLA64 view; and the rules of
 * ildasm's that the large assemblies taught, on small cases — quoting names,
 * breaking parameter lists at commas, floating-point constants.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';
import { referenceLines } from '../tools/ildasm-text.mjs';

const { check, done } = checker();
const C = await load('core/pe', 'core/cil/metadata', 'core/cil/names', 'core/cil/opcodes', 'core/cil/decode', 'core/cil/program', 'core/cil/hla', 'core/rows', 'core/catalog');
const dir = join(root, 'tests', 'fixtures', 'dotnet');
const bytes = new Uint8Array(readFileSync(join(dir, 'hello.dll')));

/* ---------------- the decoder, against ildasm ---------------- */

const expected = referenceLines(readFileSync(join(dir, 'hello.il'), 'utf8'));
const pe = C.parsePe(bytes);
check('a .NET assembly', pe.clr, true);
const md = C.readMetadata(pe);
const names = new C.Names(md);
const insn = new C.CilInsn();
const ours = new Map();
for (let m = 1; m <= md.rows(C.TABLE.MethodDef); m++) {
  const body = md.body(m);
  if (!body) continue;
  const ctx = C.methodContext(md, names, m);
  for (let pos = body.code; pos < body.code + body.size; pos += insn.len) {
    C.decodeAt(md.bytes, body.code, pos, body.code + body.size, insn);
    const raw = md.bytes.subarray(pos + insn.len - (insn.op?.operand === C.OPERAND.R4 ? 4 : 8), pos + insn.len);
    ours.set(`${body.rva}:${insn.at}`, C.insnText(md, insn, ctx, raw));
  }
}
let wrong = 0;
for (const [key, want] of expected) {
  if (ours.get(key) !== want && wrong++ < 20) check(key, ours.get(key), want);
}
check(`all ${expected.size} instructions match ildasm`, [wrong, ours.size], [0, expected.size]);

/* ---------------- metadata ---------------- */

check('metadata version', md.version, 'v4.0.30319');
check('streams', md.streams.map((s) => s.name), ['#~', '#Strings', '#US', '#GUID', '#Blob']);
check('#US', md.userStrings().some((s) => s.text === '--help'), true);
check('a fat body with clauses', md.body(names.methodOwner.findIndex((_, m) => m && md.string(md.table(C.TABLE.MethodDef).get(m, 'Name')) === 'Main'))?.clauses.map((c) => c.kind), [0, 2]);
check('compressed integers', [C.compressed(Uint8Array.of(0x03), 0), C.compressed(Uint8Array.of(0x80, 0x80), 0), C.compressed(Uint8Array.of(0xc0, 0, 0x40, 0), 0)], [[3, 1], [128, 2], [0x4000, 4]]);

/* ---------------- the analysis ---------------- */

const p = await C.analyzeCil(pe);
const fn = (name) => p.functions.find((f) => f.name === name);
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
const regions = [...p.regions].filter(([index]) => index >= main.first && index < main.first + main.count).map(([, list]) => list.map((r) => `${r.part}:${r.clause.kind}`).join());
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
    const line = C.liftGroup(p, first, i);
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
      if (C.liftGroup(p, first, i)) lifted++;
    } catch {
      errors++;
    }
  }
}
check('hla: every row lifts or stays instructions', errors, 0);
check('hla: most rows read as HLA64', lifted / lines > 0.45, true);
check('hla: unsigned only between integers', [C.kindOf('int32'), C.kindOf('float64'), C.kindOf('class [System.Runtime]System.String'), C.kindOf('uint8&'), C.kindOf('valuetype X')], ['i', 'f', 'r', 'p', undefined]);
check('hla: float literals', [C.floatLiteral(1, false), C.floatLiteral(0.1, true), C.floatLiteral(Math.fround(6.2831855), true), C.floatLiteral(NaN, false)], ['1.0', '0.1', '6.2831855', 'nan']);
check('hla: short types', C.shortType('class [System.Collections]System.Collections.Generic.List`1<valuetype [System.Runtime]System.ValueTuple`2<int32,string>>'), 'List<ValueTuple<int32,string>>');

/* ---------------- ildasm's rules ---------------- */

check('names that need quotes', ['Main', '<>c', 'value', 'Value', '.ctor', '.cctor', 'Func`2', 'a.b', 'a..b', 'x.', '#x', '_$@', '?x', 'x?', 'Привет', 'async', 'ldc.i4'].map(C.needsQuotes),
  [false, true, true, false, false, false, false, false, true, true, false, false, true, false, true, true, true]);
check('quoted names are escaped', C.properName("process'@347"), "'process\\'@347'");
check('a local name with a dot is quoted', [C.properLocalName('a.b'), C.properName('a.b')], ["'a.b'", 'a.b']);
// SplitSignatureByCommas: a comma breaks the line only where nothing is open since the line began.
check('split: a plain list', C.splitCommas('void A::f(int32,string)', 10), 'void A::f(int32, string)');
check('split: generics stay', C.splitCommas('void A::f(class X`2<int32,int32>,int32)', 10), 'void A::f(class X`2<int32,int32>, int32)');
check('split: a function pointer first', C.splitCommas('int32 A::f(method void *(void*,uint8*),void*)', 11), 'int32 A::f(method void *(void*,uint8*), void*)');
check('split: a function pointer after a break', C.splitCommas('int32 A::f(object,method void *(void*,uint8*),void*)', 11), 'int32 A::f(object, method void *(void*, uint8*),void*)');
check('split: an escaped quote stops it', C.splitCommas("void A::'f\\'1'(int32,int32)", 15), "void A::'f\\'1'(int32,int32)");
check('floats as %g', [C.gFormat(1, 8), C.gFormat(0.1, 8), C.gFormat(3.4e38, 8), C.gFormat(1e-7, 8), C.gFormat(0.1, 17), C.gFormat(123456789.125, 17), C.gFormat(-0, 8)],
  ['1', '0.1', '3.4e+38', '1e-07', '0.10000000000000001', '123456789.125', '-0.0']);
check('strings: escapes, bytes', [C.stringText('a\t"b"?\\'), C.stringText('é')], ['"a\\t\\"b\\"\\?\\\\"', 'bytearray (E9 00)']);

done('cil');
