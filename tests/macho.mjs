/**
 * The Mach-O reader on tests/fixtures/hello (a small arm64 program built by
 * clang from hello.c), on the same program wrapped as a universal file, and
 * on things that are not Mach-O at all. Then the analysis of the whole
 * program: functions, names, strings, statistics. Then 32-bit programs
 * (tests/fixtures/macho32): armv7 for iOS, stripped and not, with
 * Objective-C, in a universal file with arm64, and i386 for old macOS.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const { check, done } = checker();
const M = await load('core/macho', 'core/program', 'core/image', 'core/objc', 'core/arm32/program', 'core/x86/program');
const bytes = new Uint8Array(readFileSync(join(root, 'tests', 'fixtures', 'hello')));
const image = M.parseMachO(bytes);

check('arch', image.arch, 'arm64');
check('type', image.fileTypeName, 'Executable');
check('PIE', image.flagNames.includes('PIE'), true);
check('segments', image.segments.map((s) => s.name), ['__PAGEZERO', '__TEXT', '__DATA_CONST', '__DATA', '__LINKEDIT']);
check('__text exists', !!image.sections.find((s) => s.sectname === '__text'), true);
check('libSystem', image.libraries.some((l) => l.includes('libSystem')), true);
const imported = image.imports.map((i) => i.name);
for (const name of ['_printf', '_puts', '_strcmp']) check(`imports ${name}`, imported.includes(name), true);
check('imports name their library', image.imports.find((i) => i.name === '_printf')?.library, '/usr/lib/libSystem.B.dylib');
check('main is exported', image.exports.some((e) => e.name === '_main'), true);
const main = image.exports.find((e) => e.name === '_main');
check('entry point is main', image.entry, main.addr);
check('UUID', /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/.test(image.uuid ?? ''), true);
check('build version', image.build?.platform, 'macOS');
check('function starts', image.functionStarts.length >= 4, true);
check('signed', image.signature?.hashType, 'SHA-256');
check('stubs are named', [...image.stubs.values()].includes('_printf'), true);
check('C string', M.cstringAt(image, image.sections.find((s) => s.sectname === '__cstring').addr), 'zero');

// A universal file opens at its arm64 slice.
const fat = new Uint8Array(0x4000 + bytes.length);
const view = new DataView(fat.buffer);
view.setUint32(0, 0xcafebabe);
view.setUint32(4, 2);
view.setUint32(8, 0x01000007); // x86_64 first
view.setUint32(16, 0x4000);
view.setUint32(20, 16);
view.setUint32(28, 0x0100000c); // then arm64
view.setUint32(36, 0x4000);
view.setUint32(40, bytes.length);
fat.set(bytes, 0x4000);
const fromFat = M.parseMachO(fat);
check('universal: arches', fromFat.arches.map((a) => a.name), ['x86_64', 'arm64']);
check('universal: opens arm64', [fromFat.arch, fromFat.exports.length], ['arm64', image.exports.length]);

// Not Mach-O.
const fails = (data) => {
  try {
    M.parseMachO(data);
    return false;
  } catch (error) {
    return error instanceof M.NotMachO;
  }
};
check('text is refused', fails(new TextEncoder().encode('#!/bin/sh\necho hello, this is not a program at all\n')), true);
check('too short is refused', fails(new Uint8Array(4)), true);

// The analysis.
const stages = [];
const program = await M.analyze(M.fromMachO(image), (stage) => stages.push(stage));
check('stages reported', [...new Set(stages)], ['decode', 'functions', 'done']);
check('every word decoded', program.totalInstructions, image.sections.filter((s) => s.flags & 0x80000000).reduce((n, s) => n + s.size / 4, 0));
const names = program.functions.map((f) => f.name);
for (const name of ['main', 'sum', 'kind', 'average', 'printf', 'puts']) check(`function ${name}`, names.includes(name), true);
check('imports are functions of their stubs', program.functions.find((f) => f.name === 'printf')?.kind, 'import');
check('sum is called', (program.callers.get(program.functions.find((f) => f.name === 'sum').addr) ?? []).length >= 2, true);
check('counts add up', program.counts.reduce((n, c) => n + c.count, 0), program.totalInstructions);
check('counts sorted', program.counts.every((c, i, all) => i === 0 || all[i - 1].count >= c.count), true);
check('format string found', program.strings.some((s) => s.text.startsWith('Hello, world!')), true);
check('string is referenced', program.strings.filter((s) => s.text.startsWith('Hello')).every((s) => (program.dataRefs.get(s.addr) ?? []).length > 0), true);
const mainFn = program.functionAt(main.addr);
check('functionAt', mainFn?.name, 'main');
check('functionOfIndex', program.functions[program.functionOfIndex(program.indexOf(main.addr) + 3)]?.name, 'main');
check('indexOf / addrOf round trip', program.addrOf(program.indexOf(main.addr + 8)), main.addr + 8);

// 32-bit programs.
const m32 = (name, slice) => M.parseMachO(new Uint8Array(readFileSync(join(root, 'tests', 'fixtures', 'macho32', name))), slice);
const namedFns = (p) => p.functions.filter((f) => f.kind !== 'anonymous').map((f) => `${f.name}:${f.kind}`).sort();
const greeting = (p) => p.dataRefs.get(p.strings.find((s) => s.text.startsWith('Hello, x86!'))?.addr)?.length ?? 0;
{
  const armv7 = m32('hello-armv7');
  check('armv7: header', [armv7.arch, armv7.is64, armv7.fileTypeName, armv7.segments.map((s) => s.name)], ['armv7', false, 'Executable', ['__PAGEZERO', '__TEXT', '__DATA', '__LINKEDIT']]);
  check('armv7: imports through 4-byte pointer slots', ['_printf', '_strcmp', '___divsi3'].map((n) => armv7.imports.find((i) => i.name === n)?.slot !== undefined), [true, true, true]);
  check('armv7: Thumb function starts keep their low bit', armv7.functionStarts.every((a) => a & 1), true);
  const image32 = M.fromMachO(armv7);
  check('armv7: platform, entry in Thumb, data in code', [M.platformOf(image32)?.label, image32.entry & 1, image32.dataInCode.length], ['iOS 9.0+', 1, 1]);
  const p = await M.analyzeArm32(image32);
  check('armv7: functions with names', namedFns(p), ['__divsi3:import', '__stack_chk_fail:import', 'main:entry', 'printf:import', 'puts:import', 'strcmp:import']);
  check('armv7: Thumb-2 code, the greeting, the switch, nothing undecoded',
    [p.isThumb(p.functions.find((f) => f.name === 'main').first), greeting(p), [...p.tables].map(([, t]) => t.length), p.counts.find((c) => c.mnemonic === '<unknown>')?.count ?? 0], [true, 1, [8], 0]);
  // The stripped layout against the one the symbols (N_ARM_THUMB_DEF) give.
  const full = await M.analyzeArm32(M.fromMachO(m32('hello-armv7.full')));
  check('armv7: the symbols name the rest', namedFns(full).filter((n) => n.endsWith(':export')), ['main:export', 'scale4:export', 'step:export', 'sum:export']);
  const differ = [];
  for (let i = 0; i < full.totalInstructions; i++) {
    const j = p.indexOf(full.addrOf(i));
    if (j < 0 || p.addrOf(j) !== full.addrOf(i) || p.kinds[j] !== full.kinds[i]) differ.push(full.addrOf(i).toString(16));
  }
  check('armv7: stripped layout = with symbols', differ, []);
}
{
  const objcImage = m32('hello-objc-armv7');
  const objc = M.parseObjc(objcImage);
  check('armv7 Objective-C: classes and categories', [objc.classes.map((c) => `${c.name} : ${c.superclass}`), objc.categories.map((c) => `${c.name} (${c.category})`)], [['Greeter : NSObject'], ['NSString (Shouting)']]);
  check('armv7 Objective-C: methods', [...objc.classes, ...objc.categories].flatMap((c) => c.methods.map((m) => m.name)).sort(),
    ['+[Greeter defaultGreeter]', '-[Greeter .cxx_destruct]', '-[Greeter greeting]', '-[Greeter initWithName:]', '-[Greeter name]', '-[Greeter setName:]', '-[NSString shouted]']);
  check('armv7 Objective-C: constant strings', [...objc.cfstrings.values()].includes('Hello, %@!'), true);
  const p = await M.analyzeArm32(M.fromMachO(objcImage));
  const fn = p.functions.find((f) => f.name === '-[Greeter greeting]');
  check('armv7 Objective-C: methods are Thumb functions', [!!fn, fn && p.isThumb(fn.first)], [true, true]);
  const names = new Set();
  for (const [, addr] of p.addressAt) {
    const d = p.dataAt(addr);
    if (d) names.add(d.kind === 'string' ? `@"${d.text}"` : d.name);
  }
  check('armv7 Objective-C: the code names selectors, classes and NSStrings', ['selref.greeting', 'classref.NSArray', '@"Hello, %@!"'].filter((n) => !names.has(n)), []);
}
{
  const universal = m32('hello-ios-universal');
  check('universal armv7 + arm64: opens at arm64', [universal.arch, universal.arches.map((a) => a.name)], ['arm64', ['armv7', 'arm64']]);
  check('universal: the armv7 slice', m32('hello-ios-universal', 'armv7').is64, false);
}
{
  const i386 = m32('hello-i386');
  check('i386: header and the entry from LC_UNIXTHREAD', [i386.arch, i386.is64, i386.entryKind, i386.commands.some((c) => c.name === 'LC_UNIXTHREAD')], ['i386', false, 'thread', true]);
  const image386 = M.fromMachO(i386);
  check('i386: platform', M.platformOf(image386)?.label, 'macOS 10.6+');
  const p = await M.analyzeX86(image386);
  check('i386: 32-bit code; the entry is crt1\'s start', [p.mode, p.functions.find((f) => f.kind === 'entry')?.name], [32, 'start']);
  check('i386: stubs name the imports', ['printf', 'puts', 'strcmp', 'exit'].filter((n) => p.functions.find((f) => f.name === n)?.kind !== 'import'), []);
  check('i386: the greeting and the switch', [greeting(p), [...p.tables].map(([, t]) => t.length)], [1, [8]]);
}

done('macho');
