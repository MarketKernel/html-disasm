/**
 * Windows on Arm: tests/fixtures/winarm (built by build.sh there). hello.c for arm64 and for
 * 32-bit Arm (Thumb-2), two DLLs that call imports through the import address table as MSVC does,
 * and two hybrid DLLs — ARM64EC beside x64, and ARM64X — whose code map says which code is which.
 * Then how a stripped Windows program's main is found, rule by rule.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const { check, done } = checker();
const M = await load('core/pe', 'core/image', 'core/program', 'core/arm32/program', 'core/x86/program', 'core/disassembly');
const fixture = (name) => M.parsePe(new Uint8Array(readFileSync(join(root, 'tests', 'fixtures', 'winarm', name))));
const named = (p, name) => p.functions.find((f) => f.name === name);
const usesString = (p, fn, text) => {
  const s = p.strings.find((x) => x.text.startsWith(text));
  return !!s && (p.dataRefs.get(s.addr) ?? []).some((pc) => {
    const i = p.indexOf(pc);
    return i >= fn.first && i < fn.first + fn.count;
  });
};

// arm64 (MinGW): import thunks named, main found from the C runtime's call to it before _cexit.
const arm64 = await M.analyze(M.fromPe(fixture('hello-arm64.exe')));
check('arm64: platform', M.platformOf(arm64.image)?.os, 'windows');
check('arm64: the entry point is named entry', arm64.functionAt(arm64.image.entry)?.name, 'entry');
check('arm64: import thunks', ['puts', 'strcmp'].every((n) => arm64.functions.some((f) => f.kind === 'import' && f.name === n)), true);
const main64 = named(arm64, 'main');
check('arm64: main', !!main64 && usesString(arm64, main64, 'Hello, x86!'), true);

// 32-bit Arm (Thumb-2, MinGW): all Thumb, movw/movt make addresses, `movw r12; movt r12; ldr.w pc, [r12]` thunks.
const pe32 = fixture('hello-arm.exe');
check('arm: machine', pe32.machineName, 'arm (Thumb-2)');
check('arm: .pdata function starts are even', pe32.functionStarts.length > 10 && pe32.functionStarts.every((a) => a % 2 === 0), true);
const arm = await M.analyzeArm32(M.fromPe(pe32));
check('arm: only Thumb code', [...arm.kinds].every((k) => k === 1 || k === 2), true);
check('arm: import thunks', ['puts', 'strcmp'].every((n) => arm.functions.some((f) => f.kind === 'import' && f.name === n)), true);
const main32 = named(arm, 'main');
check('arm: main uses its strings through movw/movt', !!main32 && usesString(arm, main32, 'Hello, x86!') && usesString(arm, main32, '--help'), true);

// MSVC calls an import by loading its slot into a register: `ldr x8, [x8, #…]; blr x8`, `ldr r6, [r0]; blx r6`.
for (const [label, file, analyze] of [['arm64', 'imports-arm64.dll', M.analyze], ['arm', 'imports-arm.dll', M.analyzeArm32]]) {
  const p = await analyze(M.fromPe(fixture(file)));
  const called = [...p.slotCalls.values()].map((slot) => p.importSlots.get(slot)).sort();
  // ext_call is called twice through a register that keeps it across the first call.
  check(`${label}: calls through import slots`, called, ['ext_call', 'ext_call', 'ext_log']);
  const slot = [...p.importSlots].find(([, n]) => n === 'ext_call')[0];
  check(`${label}: slot callers`, p.slotCallers.get(slot)?.length, 2);
}

// ARM64EC: the header says x64; the code map says which code is Arm and which x64.
const ec = fixture('arm64ec.dll');
check('arm64ec: header', ec.machine, M.MACHINE.AMD64);
check('arm64ec: code map', ec.hybrid?.ranges.map((r) => [r.addr - ec.imageBase, r.kind]), [[0x1000, 'arm64ec'], [0x2000, 'x64']]);
check('arm64ec: Arm functions from the extra unwind table', ec.hybrid?.armStarts.length, 3);
const ecArm = await M.analyze(M.fromPe(ec, 'arm'));
check('arm64ec: Arm view', [ecArm.image.arch, ecArm.ranges.map((r) => r.section.label)], ['arm64ec', ['.text (ARM64EC)']]);
// The exports are x64 entry thunks; each redirects to the ARM64EC function, which takes its name.
const add = named(ecArm, 'add');
check('arm64ec: add through its redirection', add?.addr, ec.imageBase + 0x1004);
check('arm64ec: x64 code is not decoded as Arm', ecArm.indexOf(ec.imageBase + 0x2000), -1);
const ecX64 = await M.analyzeX86(M.fromPe(ec, 'x64'));
check('arm64ec: x64 view', [ecX64.image.arch, ecX64.mode], ['x86_64', 64]);
check('arm64ec: x64 functions', ['xmul', 'xcount'].map((n) => named(ecX64, n)?.addr - ec.imageBase), [0x2000, 0x2010]);
check('arm64ec: Arm code is not decoded as x64', ecX64.indexOf(ec.imageBase + 0x1004), -1);

// ARM64X: arm64 code for Arm processes too, and an x64 view made by its dynamic relocations.
const x = fixture('arm64x.dll');
check('arm64x: header', x.machine, M.MACHINE.ARM64);
check('arm64x: code map', x.hybrid?.ranges.map((r) => r.kind), ['arm64', 'arm64ec', 'x64']);
check('arm64x: native exports', x.exports.map((e) => e.name), ['add', 'native_only']);
check('arm64x: the EC view', [x.hybrid?.ec?.machine, x.hybrid?.ec?.exports.map((e) => e.name)], [M.MACHINE.AMD64, ['add', 'twice', 'xcount', 'xmul']]);
const xArm = await M.analyze(M.fromPe(x, 'arm'));
check('arm64x: both adds in the Arm view', xArm.functions.filter((f) => f.name === 'add').map((f) => f.addr - x.imageBase), [0x1000, 0x2004]);
check('arm64x: pieces of .text', xArm.image.sections.filter((s) => s.code).map((s) => s.label), ['.text (ARM64)', '.text (ARM64EC)']);
const xX64 = await M.analyzeX86(M.fromPe(x, 'x64'));
check('arm64x: x64 view named from the EC view', ['xmul', 'xcount'].every((n) => named(xX64, n)), true);

// How main is found, rule by rule, is checked in the core (crates/core/tests/native.rs).

done('winarm');
