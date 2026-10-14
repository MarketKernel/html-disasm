/**
 * ELF and the analysis of Android libraries, on the two builds of
 * tests/fixtures/android/hello.c (+ arm.c): arm64-v8a, and armeabi-v7a with
 * Thumb-2 and A32 code side by side. Each is stripped as in an APK; the
 * armeabi-v7a one is also kept with its symbol table (.full.so), whose
 * mapping symbols say exactly which bytes are A32, T32 and data — the
 * stripped library must come out the same without them. Then Linux programs for arm64 and
 * armhf (tests/fixtures/linux).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const { check, done } = checker();
const M = await load('core/elf', 'core/image', 'core/program', 'core/arm32/program', 'core/arm32/types', 'core/zip');
const fixture = (name) => new Uint8Array(readFileSync(join(root, 'tests', 'fixtures', 'android', name)));

// The reader.
const v7 = M.parseElf(fixture('libhello-armeabi-v7a.so'));
check('armeabi-v7a header', [v7.arch, v7.is64, v7.typeName, v7.flagNames], ['armv7', false, 'Shared library', ['EABI5', 'soft-float']]);
check('needed libraries', v7.needed, ['liblog.so', 'libdl.so', 'libc.so']);
check('Android note', [v7.android?.api, v7.android?.ndk], [21, 'r29']);
check('imports and their libraries', v7.imports.map((i) => `${i.name}@${i.version ?? ''}:${i.library}`).sort(), [
  '__android_log_print@:liblog.so', '__android_log_write@:liblog.so', '__cxa_atexit@LIBC:libc.so', '__cxa_finalize@LIBC:libc.so',
  'free@LIBC:libc.so', 'malloc@LIBC:libc.so', 'strcmp@LIBC:libc.so', 'strncpy@LIBC:libc.so',
]);
const jni = v7.exports.find((e) => e.name === 'JNI_OnLoad');
check('a Thumb export: bit 0 cleared, marked', [jni?.addr % 2, jni?.thumb], [0, true]);
check('an A32 export', v7.exports.find((e) => e.name === 'scale')?.thumb, undefined);
check('GOT slots named', [...v7.slots.values()].includes('strcmp'), true);
check('stripped: no symbol table', [v7.symtab.length, v7.marks.length], [0, 0]);
check('Arm attributes', Object.fromEntries(v7.attributes).Thumb, 'Thumb-2');
const full = M.parseElf(fixture('libhello-armeabi-v7a.full.so'));
check('mapping symbols', [full.marks.some((m) => m.kind === 't'), full.marks.some((m) => m.kind === 'a'), full.marks.some((m) => m.kind === 'd')], [true, true, true]);
const a64 = M.parseElf(fixture('libhello-arm64-v8a.so'));
check('arm64 header', [a64.arch, a64.is64, a64.relocationFormats], ['arm64', true, ['RELA']]);
check('Android, by its note', [M.platformOf(M.fromElf(a64)), M.abiOf(M.fromElf(a64)), M.abiOf(M.fromElf(v7))], [{ os: 'android', label: 'Android 5.0+' }, 'arm64-v8a', 'armeabi-v7a']);
check('Android, by Bionic symbol versions alone', M.platformOf({ ...M.fromElf(v7), elf: { ...v7, android: undefined } })?.label, 'Android');
check('arm64 unwind table lists functions', a64.functionStarts.length > 10, true);
check('arm64 relative relocations', a64.relative.size > 0, true);
check('not ELF', (() => {
  try {
    M.parseElf(new Uint8Array(64));
    return 'read';
  } catch (err) {
    return err instanceof M.NotElf;
  }
})(), true);

// arm64-v8a: the same analysis as for a Mach-O program.
const p64 = await M.analyze(M.fromElf(a64));
const named = (p, name) => p.functions.find((f) => f.name === name);
check('arm64 functions', ['Java_com_example_hello_Native_greet', 'JNI_OnLoad', 'sum', 'kind', 'checksum'].map((n) => !!named(p64, n)), [true, true, true, true, true]);
check('arm64 PLT stubs: imports by name, own functions as name@plt', [named(p64, 'malloc')?.kind, named(p64, '__android_log_print')?.kind, named(p64, 'sum@plt')?.kind], ['import', 'import', 'symbol']);
check('arm64 strings', ['hello', 'Hello, world!', 'many'].map((s) => p64.strings.some((r) => r.text === s)), [true, true, true]);
const greet64 = named(p64, 'Java_com_example_hello_Native_greet');
const calls64 = [];
for (let i = greet64.first; i < greet64.first + greet64.count; i++) {
  const insn = p64.insn(i);
  if (insn.f & M.F.CALL && insn.target !== undefined) calls64.push(p64.functionAt(insn.target)?.name);
}
check('arm64 calls through the PLT', ['__android_log_print', 'malloc', 'strncpy', 'free'].every((n) => calls64.includes(n)), true);

// armeabi-v7a, stripped: the instruction sets are worked out.
const p32 = await M.analyzeArm32(M.fromElf(v7));
check('worked out, not mapped', p32.mapped, false);
const set = (p, name) => {
  const fn = named(p, name);
  return fn ? (p.isThumb(fn.first) ? 'T32' : 'A32') : undefined;
};
check('instruction set per function', ['sum', 'kind', 'average', 'add_vectors', 'JNI_OnLoad', 'scale', 'checksum'].map((n) => set(p32, n)), ['T32', 'T32', 'T32', 'T32', 'T32', 'A32', 'A32']);
check('PLT stubs', [named(p32, 'malloc')?.kind, named(p32, '__android_log_write')?.kind, named(p32, 'scale@plt')?.kind, set(p32, 'malloc')], ['import', 'import', 'symbol', 'A32']);
check('strings', ['hello', 'loaded', 'Hello, world!', 'Hello, many!', 'sum=%ld avg=%.2f kind=%s scaled=%ld'].map((s) => p32.strings.some((r) => r.text === s)), [true, true, true, true, true]);
check('no strings made of an int array', p32.strings.some((r) => r.text === '*'), false);

// JNI_OnLoad: ldr r1, [pc, #…] / add r1, pc makes the address of "hello".
const onload = named(p32, 'JNI_OnLoad');
const madeAddresses = [];
for (let i = onload.first; i < onload.first + onload.count; i++) {
  const addr = p32.addressAt.get(i);
  const data = addr !== undefined ? p32.dataAt(addr) : undefined;
  if (data?.kind === 'string') madeAddresses.push(`${M.formatInsn(p32.insn(i)).split(' ')[0]} ${data.text}`);
}
check('literal + add pc → string', madeAddresses, ['ldr hello', 'add hello', 'ldr loaded', 'add loaded']);
check('literal pool is data', (() => {
  const last = onload.first + onload.count - 1;
  return [p32.isData(last), p32.insn(last).m];
})(), [true, '.word']);
check('calls from T32 to A32 through blx', (() => {
  const greet = named(p32, 'Java_com_example_hello_Native_greet');
  const out = [];
  for (let i = greet.first; i < greet.first + greet.count; i++) {
    const insn = p32.insn(i);
    if (insn.f & M.F.CALL && insn.target !== undefined) out.push(`${insn.m} ${p32.functionAt(insn.target)?.name}`);
  }
  return out.slice(0, 4);
})(), ['blx sum@plt', 'blx average@plt', 'blx kind@plt', 'blx scale@plt']);
check('IT blocks carry their condition', (() => {
  const sum = named(p32, 'sum');
  return [M.formatInsn(p32.insn(sum.first + 1)), M.formatInsn(p32.insn(sum.first + 2)), p32.its[sum.first + 2]];
})(), ['itt lt', 'movlt r0, #0x0', 11]);
check('GOT load names the import', (() => {
  for (const [i, addr] of p32.addressAt) if (p32.dataAt(addr)?.name === 'got.strcmp' && p32.insn(i).m === 'ldr') return true;
  return false;
})(), true);
check('labels inside functions', [...p32.flags].some((f) => f & 1), true);

// The same library with its mapping symbols: the layout the stripped one worked out must be identical.
const mapped = await M.analyzeArm32(M.fromElf(full));
check('mapped', mapped.mapped, true);
const differ = [];
for (let i = 0; i < mapped.totalInstructions; i++) {
  const j = p32.indexOf(mapped.addrOf(i));
  if (j < 0 || p32.addrOf(j) !== mapped.addrOf(i) || p32.kinds[j] !== mapped.kinds[i]) differ.push(mapped.addrOf(i).toString(16));
}
check('stripped layout = mapping symbols (except the PLT padding)', differ.filter((a) => parseInt(a, 16) < 0xff0), []);
check('mapped library names its static functions', !!named(mapped, '__on_dlclose'), true);

// Linux programs (glibc, tests/fixtures/linux/build.sh), stripped: main is what _start hands to
// __libc_start_main, through a literal, adr, or the GOT; the armhf ones lay out as their
// mapping symbols say, in A32 and in Thumb-2 (with glibc's _start in A32).
const linux = (name) => M.fromElf(M.parseElf(new Uint8Array(readFileSync(join(root, 'tests', 'fixtures', 'linux', name)))));
const callsFrom = (p, fn) => {
  const out = [];
  for (let i = fn.first; i < fn.first + fn.count; i++) {
    if (p.isData?.(i)) continue;
    const insn = p.insn(i);
    if (insn.f & M.F.CALL && insn.target !== undefined) out.push(p.functionAt(insn.target)?.name);
  }
  return out;
};
const greetingRefs = (p) => p.dataRefs.get(p.strings.find((s) => s.text.startsWith('Hello, x86!'))?.addr)?.length ?? 0;
{
  const image = linux('hello-linux-arm64');
  const p = await M.analyze(image);
  check('Linux arm64: platform and ABI', [M.platformOf(image)?.label, M.abiOf(image)], ['Linux', 'arm64']);
  check('Linux arm64: functions with names', p.functions.filter((f) => f.kind !== 'anonymous').map((f) => `${f.name}:${f.kind}`).sort(),
    ['__libc_start_main:import', '_start:entry', 'abort:import', 'main:symbol', 'printf:import', 'puts:import', 'step:export', 'strcmp:import']);
  check('Linux arm64: the first PLT stub, after the header\'s nops', callsFrom(p, named(p, '_start')), ['__libc_start_main', 'abort']);
  check('Linux arm64: main calls libc by name', ['printf', 'strcmp', 'puts'].every((n) => callsFrom(p, named(p, 'main')).includes(n)), true);
  check('Linux arm64: the greeting', greetingRefs(p), 1);
}
for (const [file, sets] of [['hello-linux-armhf', ['A32', 'A32', 'A32']], ['hello-linux-armhf-thumb', ['A32', 'T32', 'T32']]]) {
  const image = linux(file);
  const p = await M.analyzeArm32(image);
  check(`${file}: platform, ABI, float ABI`, [M.platformOf(image)?.label, M.abiOf(image), image.elf.flagNames], ['Linux', 'armv7', ['EABI5', 'hard-float']]);
  check(`${file}: functions with names`, p.functions.filter((f) => f.kind !== 'anonymous').map((f) => `${f.name}:${f.kind}`).sort(),
    ['__libc_start_main:import', '_start:entry', 'abort:import', 'main:symbol', 'printf:import', 'puts:import', 'step:export', 'strcmp:import']);
  check(`${file}: instruction sets of _start, main, step`, ['_start', 'main', 'step'].map((n) => set(p, n)), sets);
  check(`${file}: _start calls`, callsFrom(p, named(p, '_start')), ['__libc_start_main', 'abort']);
  check(`${file}: the greeting, and no string made of the GOT's offset`, [greetingRefs(p), p.strings.filter((s) => s.text.includes('Hello') || s.text.includes('scaled')).length], [1, 1]);
  check(`${file}: the switch and its eight cases`, [...p.tables].map(([i, targets]) => `${p.functions[p.functionOfIndex(i)]?.name}:${targets.length}`), ['step:8']);
  const mapped = await M.analyzeArm32(linux(`${file}.full`));
  const differ = [];
  for (let i = 0; i < mapped.totalInstructions; i++) {
    const j = p.indexOf(mapped.addrOf(i));
    if (j < 0 || p.addrOf(j) !== mapped.addrOf(i) || p.kinds[j] !== mapped.kinds[i]) differ.push(mapped.addrOf(i).toString(16));
  }
  check(`${file}: stripped layout = mapping symbols`, [mapped.mapped, differ], [true, []]);
}

// An APK is a ZIP: its libraries are listed by ABI, stored or deflated; a bundle of split APKs
// has them in the APKs inside it.
const apk = new Uint8Array(readFileSync(join(root, 'tests', 'fixtures', 'android', 'hello.apk')));
const libs = await M.packagedLibraries(apk);
check('APK libraries', libs.map((l) => `${l.abi}/${l.file}`).sort(), ['arm64-v8a/libhello.so', 'armeabi-v7a/libhello.so']);
const methods = M.zipEntries(apk).filter((e) => e.name.endsWith('.so')).map((e) => e.method).sort();
check('stored and deflated entries', methods, [0, 8]);
const readBack = async (l) => Buffer.from(await l.read());
check('read back', [
  (await readBack(libs.find((l) => l.abi === 'armeabi-v7a'))).equals(Buffer.from(fixture('libhello-armeabi-v7a.so'))),
  (await readBack(libs.find((l) => l.abi === 'arm64-v8a'))).equals(Buffer.from(fixture('libhello-arm64-v8a.so'))),
], [true, true]);
const bundle = await M.packagedLibraries(new Uint8Array(readFileSync(join(root, 'tests', 'fixtures', 'android', 'hello.apks'))));
check('split APKs', bundle.map((l) => `${l.from} ${l.abi}/${l.file}`).sort(), ['split_config.arm64_v8a.apk arm64-v8a/libhello.so', 'split_config.armeabi_v7a.apk armeabi-v7a/libhello.so']);
check('read from a split APK', (await readBack(bundle.find((l) => l.abi === 'arm64-v8a'))).equals(Buffer.from(fixture('libhello-arm64-v8a.so'))), true);

done('elf');
