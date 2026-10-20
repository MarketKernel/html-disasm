/**
 * iOS programs: property lists and provisioning profiles, the bundles of an
 * .ipa, and the Objective-C metadata of tests/fixtures/ios (built by build.sh
 * there): classes, categories and their methods, selector and class
 * references, constant NSStrings and objc_msgSend stubs, checked against
 * what `xcrun dyld_info -objc` and the linker's symbols say. Then the
 * analysis: methods name their functions, and HLA64 writes @"…".
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const { check, done } = checker();
const M = await load('core/archive', 'core/macho', 'core/image', 'core/program', 'core/rows', 'core/hla', 'core/arm64/decode');
const fixture = (name) => new Uint8Array(readFileSync(join(root, 'tests', 'fixtures', 'ios', name)));

// Property lists and provisioning profiles: crates/core/tests/bundle.rs.

// The .ipa: the app and its framework, named by their binary Info.plists.
const programs = await M.bundledPrograms(fixture('Hello.ipa'));
check('ipa programs', programs.map((p) => `${p.bundle.kind}:${p.file}`).sort(), ['app:Hello', 'framework:HelloKit']);
const app = programs.find((p) => p.bundle.kind === 'app');
check('app bundle', [app?.bundle.path, app?.bundle.identifier, app?.bundle.version, app?.bundle.build, app?.bundle.minimumOS], ['Payload/Hello.app', 'com.example.hello', '1.2', '34', '15.0']);
check('app platforms', app?.bundle.platforms, ['iPhoneOS']);
const appBytes = await app.read();
check('the app is the stripped executable', appBytes.length, fixture('Hello').length);

// Objective-C metadata, as `xcrun dyld_info -objc Hello` lists it.
const hello = M.parseMachO(fixture('Hello'));
check('iOS', hello.build?.platform, 'iOS');
check('not encrypted', [hello.encrypted, hello.encryption?.id], [false, 0]);
const expected = [
  '100004000 -[Greeter initWithName:]',
  '100004078 -[Greeter greeting]',
  '100004104 -[Greeter name]',
  '10000410c -[Greeter setName:]',
  '100004114 -[Greeter .cxx_destruct]',
  '1000040dc +[Greeter defaultGreeter]',
  '100004120 -[NSString shouted]',
];
const methodsOf = (objc) => [...objc.classes, ...objc.categories].flatMap((c) => c.methods.map((m) => `${m.imp.toString(16)} ${m.name}`));
for (const [label, file] of [['chained fixups', 'Hello'], ['bind opcodes', 'HelloClassic']]) {
  const m = file === 'Hello' ? hello : M.parseMachO(fixture(file));
  const objc = M.fromMachO(m).objc;
  // HelloClassic is linked separately: its code is at other addresses, but the methods are the same.
  check(`methods (${label})`, methodsOf(objc).map((s) => s.replace(/^\w+ /, '')), expected.map((s) => s.replace(/^\w+ /, '')));
  check(`class and superclass (${label})`, objc.classes.map((c) => `${c.name} : ${c.superclass}`), ['Greeter : NSObject']);
  check(`category (${label})`, objc.categories.map((c) => `${c.name} (${c.category})`), ['NSString (Shouting)']);
  check(`class references (${label})`, [...new Set(objc.classrefs.values())].sort(), ['Greeter', 'NSArray', 'NSString']);
  check(`constant strings (${label})`, [...objc.cfstrings.values()].includes('Hello, %@!'), true);
  check(`objc_msgSend stubs (${label})`, objc.stubs.size, 11);
}
check('method addresses', methodsOf(M.fromMachO(hello).objc), expected);
const helloObjc = M.fromMachO(hello).objc;
check('selectors', ['init', 'initWithName:', 'defaultGreeter', 'greeting'].every((s) => [...helloObjc.selrefs.values()].includes(s)), true);
// The linker's names for the stubs (nm on the unstripped build): _objc_msgSend$copy at 0x100004340.
check('stub selectors', [helloObjc.stubs.get(0x100004320), helloObjc.stubs.get(0x100004340), helloObjc.stubs.get(0x1000043c0)], ['arrayWithObjects:', 'copy', 'initWithName:']);

// Classic bind opcodes step back with 64-bit wraparound (ADD_ADDR_ULEB 0xffff…d8): every slot stays in the image.
const classic = M.parseMachO(fixture('HelloClassic'));
check('bind slots in the image', [...classic.stubs.keys()].every((a) => a >= 0x100000000 && a < 0x100010000), true);
check('bind slot names', [classic.stubs.get(0x10000c1f0), classic.stubs.get(0x10000c230), classic.stubs.get(0x100008158)], ['_OBJC_CLASS_$_NSArray', '_OBJC_METACLASS_$_NSObject', '_objc_msgSend']);

// The last pointer of a fixup chain has no next link, but it is still a rebase: the metaclass's class_ro_t.
check('last link of a chain', hello.rebases.get(0x10000c1f0), 0x10000c000);

// A program the App Store encrypted (cryptid 1) is known as such.
const encrypted = fixture('Hello').slice();
const encryptionCommand = hello.commands.find((c) => c.name === 'LC_ENCRYPTION_INFO_64');
new DataView(encrypted.buffer).setUint32(encryptionCommand.offset + 16, 1, true);
const fairplay = M.parseMachO(encrypted);
check('FairPlay', [fairplay.encrypted, fairplay.encryption?.offset, fairplay.encryption?.size > 0], [true, 0x4000, true]);

// The analysis: methods and stubs name functions, and Objective-C data names what the code loads.
const image = M.fromMachO(hello);
const program = await M.analyze(image);
const named = (addr) => program.functionAt(addr)?.name;
check('method names', [named(0x100004000), named(0x1000040dc), named(0x100004120)], ['-[Greeter initWithName:]', '+[Greeter defaultGreeter]', '-[NSString shouted]']);
check('stub names', named(0x100004340), 'objc_msgSend$copy');
const selref = [...helloObjc.selrefs].find(([, s]) => s === 'init')[0];
check('selector reference', program.dataAt(selref), { kind: 'symbol', name: 'selref.init' });
const classref = [...helloObjc.classrefs].find(([, c]) => c === 'NSString')[0];
check('class reference', program.dataAt(classref), { kind: 'symbol', name: 'classref.NSString' });
const cfstring = [...helloObjc.cfstrings].find(([, s]) => s === 'Hello, %@!')[0];
check('NSString constant', program.dataAt(cfstring), { kind: 'string', text: 'Hello, %@!', objc: true });
check('NSString is not a C string', program.strings.some((s) => s.addr === cfstring), false);

const hla = M.buildRows(program, 'hla');
const context = program.context();
const lines = [];
for (let r = 0; r < hla.count; r++) {
  if (hla.kind[r] !== 0) continue;
  const i = hla.value[r];
  const next = program.flags[i] & 2 ? { word: program.words[i + 1], pc: program.addrOf(i + 1) } : undefined;
  const line = M.liftArm64(program.words[i], program.addrOf(i), context, next);
  lines.push(line.text);
}
const text = lines.join('\n');
check('HLA64 NSString', text.includes('x2 = @"Hello, %@!"'), true);
check('HLA64 stub call', text.includes('`objc_msgSend$initWithName:`()'), true);
check('HLA64 class reference', text.includes('[&`classref.Greeter`]'), true);

// The Swift framework: its functions are named as swift-demangle --simplified names them, in full in the details.
const kit = await M.analyze(M.fromMachO(M.parseMachO(await programs.find((p) => p.file === 'HelloKit').read())));
const swiftNamed = (name) => kit.functions.find((f) => f.name === name);
check('Swift functions named', ['Counter.increment(by:)', '@objc Counter.increment(by:)', 'helloKitAnswer(_:)', 'Counter.__allocating_init()', 'Counter.count.getter'].filter((n) => !swiftNamed(n)), []);
check('Swift full name and language', [swiftNamed('Counter.increment(by:)')?.full, swiftNamed('Counter.increment(by:)')?.language], ['HelloKit.Counter.increment(by: Swift.Int) -> Swift.Int', 'swift']);

done('ios');
