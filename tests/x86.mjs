/**
 * The x86 decoder against the text llvm-objdump -M intel prints: every
 * vector in tests/fixtures/x86-vectors.json (made by tools/verify-x86.mjs
 * from random encodings and real code), and the cases where LLVM's way of
 * reading x86 is worth pinning down.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const { decodeX86, printX86, formatX86, loadX86, LLVM_VERSION } = await load('core/x86/decode', 'core/x86/print', 'core/x86/tables');
await loadX86();
const { check, done } = checker();

const hex = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const line = (bytes, addr = 0x1000, mode = 64) => {
  const code = typeof bytes === 'string' ? hex(bytes.replace(/ /g, '')) : bytes;
  const d = decodeX86(code, 0, code.length, addr, mode);
  return [formatX86(printX86(d)), d.length];
};

const { vectors } = JSON.parse(readFileSync(join(root, 'tests', 'fixtures', 'x86-vectors.json'), 'utf8'));
let wrong = 0;
for (const [bytes, addr, text, mode] of vectors) {
  const [mine, length] = line(bytes, parseInt(addr, 16), mode ?? 64);
  if (mine !== text || length !== bytes.length / 2) {
    if (wrong++ < 20) check(`${bytes} @${addr}`, [mine, length], [text, bytes.length / 2]);
  }
}
check(`${vectors.length} vectors decode as LLVM ${LLVM_VERSION} prints them`, wrong, 0);

// Ordinary code.
check('prologue', line('55'), ['push rbp', 1]);
check('mov with REX.W', line('4889e5'), ['mov rbp, rsp', 3]);
check('a store below the frame', line('48897df8'), ['mov qword ptr [rbp - 0x8], rdi', 4]);
check('a negative immediate', line('4883c480'), ['add rsp, -0x80', 4]);
check('rip-relative', line('488d0500010000', 0x17), ['lea rax, [rip + 0x100]', 7]);
check('call: the target, not the offset', line('e82d000000', 0x22), ['call 0x54', 5]);
check('call backwards past zero wraps', line('e8f0ffffff', 0), ['call 0xfffffffffffffff5', 5]);
check('movabs', line('48b88967452301000000'), ['movabs rax, 0x123456789', 10]);
check('the long nop', line('2e660f1f840000000000'), ['nop word ptr cs:[rax + rax]', 10]);
check('rep stos', line('f348ab'), ['rep stosq qword ptr es:[rdi], rax', 3]);
check('AVX-512 with mask, zeroing and broadcast', line('62f175d9fe4010'), ['vpaddd zmm0 {k1} {z}, zmm1, dword ptr [rax + 0x40]{1to16}', 7]);
check('embedded rounding', line('62f1741858c2'), ['vaddps zmm0, zmm1, zmm2, {rn-sae}', 6]);
check('a compare predicate in the mnemonic', line('0fc2c101'), ['cmpltps xmm0, xmm1', 4]);
check('endbr64', line('f30f1efa'), ['endbr64', 4]);

// Prefixes as LLVM reads them.
check('lock first is an instruction of its own', line('f00fc108'), ['lock', 1]);
check('lock after another prefix belongs to the instruction', line('66f00fc108'), ['lock xadd word ptr [rax], cx', 5]);
check('rep before an xchg is xrelease', line('f387c8'), ['xrelease', 1]);
check('pause', line('f390'), ['pause', 2]);
check('xchg r8 with REX.B, not a nop', line('4190'), ['xchg eax, r8d', 2]);
check('addr32', line('678b00'), ['mov eax, dword ptr [eax]', 3]);

// What does not decode: LLVM skips the bytes it read.
check('an undefined opcode', line('0fff'), ['<unknown>', 2]);
check('a three-byte opcode without its ModR/M byte', line('660f3aff'), ['<unknown>', 4]);
check('a lone byte', line('d6'), ['<unknown>', 1]);
check('a REX prefix with nothing after it', line('48'), ['rex64', 1]);
check('running out of bytes', line('0f'), ['<unknown>', 1]);

// i386.
check('i386: push', line('55', 0x1000, 32), ['push ebp', 1]);
check('i386: inc is one byte', line('40', 0x1000, 32), ['inc eax', 1]);
check('i386: PIC thunk call', line('e800000000', 0x1000, 32), ['call 0x1005', 5]);
check('i386: absolute address', line('a134120000', 0x1000, 32), ['mov eax, dword ptr [0x1234]', 5]);
check('i386: call wraps at 32 bits', line('e8f0ffffff', 0, 32), ['call 0xfffffff5', 5]);

// The analysis, on hello.c built for every x86 target (tests/fixtures/x86/build.sh).
const A = await load('core/x86/program', 'core/x86/hla', 'core/elf', 'core/macho', 'core/pe', 'core/image');
const open = async (name, slice) => {
  const bytes = new Uint8Array(readFileSync(join(root, 'tests', 'fixtures', 'x86', name)));
  const image = bytes[0] === 0x7f ? A.fromElf(A.parseElf(bytes)) : bytes[0] === 0x4d ? A.fromPe(A.parsePe(bytes)) : A.fromMachO(A.parseMachO(bytes, slice));
  return A.analyzeX86(image);
};
const named = (p) => p.functions.filter((f) => f.kind !== 'anonymous').map((f) => `${f.name}:${f.kind}`).sort();
const helloRefs = (p) => p.dataRefs.get(p.strings.find((s) => s.text.startsWith('Hello, x86!'))?.addr)?.length ?? 0;
const switches = (p) => [...p.tables].map(([i, targets]) => `${p.functions[p.functionOfIndex(i)]?.name}:${targets.length}`);
for (const [file, arch, platform, mode, functions] of [
  ['hello-linux-x86_64', 'x86_64', 'Linux', 64, ['_start:entry', 'main:symbol', 'printf:import', 'puts:import', 'step:export', 'strcmp:import']],
  ['hello-linux-i386', 'x86', 'Linux', 32, ['__libc_start_main:import', '_start:entry', 'main:symbol', 'printf:import', 'puts:import', 'step:export', 'strcmp:import']],
  ['libhello-x86_64.so', 'x86_64', 'Android 5.0+', 64, ['__cxa_atexit:import', '__cxa_finalize:import', 'main:export', 'printf:import', 'puts:import', 'scale4:export', 'scale4@plt:symbol', 'step:export', 'step@plt:symbol', 'strcmp:import', 'sum:export', 'sum@plt:symbol']],
  ['libhello-x86.so', 'x86', 'Android 5.0+', 32, ['__cxa_atexit:import', '__cxa_finalize:import', 'main:export', 'printf:import', 'puts:import', 'scale4:export', 'scale4@plt:symbol', 'step:export', 'step@plt:symbol', 'strcmp:import', 'sum:export', 'sum@plt:symbol']],
]) {
  const p = await open(file);
  check(`${file}: architecture, platform, mode`, [p.archLabel(), p.platformLabel(), p.mode], [arch, platform, mode]);
  check(`${file}: functions with names`, named(p), functions);
  check(`${file}: the code names the greeting`, helloRefs(p), 1);
  check(`${file}: the switch and its eight cases`, switches(p), ['step:8']);
  check(`${file}: everything decodes`, p.counts.find((c) => c.mnemonic === '<unknown>')?.count ?? 0, 0);
}
{
  const p = await open('hello-macos', 'x86_64');
  check('macOS: the x86_64 slice of a universal file', [p.archLabel(), p.mode, p.image.macho.arches.map((a) => a.name)], ['x86_64', 64, ['x86_64', 'arm64']]);
  check('macOS: functions with names', named(p), ['__stack_chk_fail:import', 'main:export', 'printf:import', 'puts:import', 'scale4:export', 'step:export', 'strcmp:import', 'sum:export']);
  check('macOS: the greeting and the switch', [helloRefs(p), switches(p)], [1, ['step:8']]);
  const main = p.functions.find((f) => f.name === 'main');
  const calls = [];
  for (let i = main.first; i < main.first + main.count; i++) {
    const insn = p.insn(i);
    if (insn.f & 4 && insn.target !== undefined) calls.push(p.target(insn.target)?.name);
  }
  check('macOS: main calls through the stubs', calls, ['sum', 'step', 'scale4', 'printf', 'strcmp', 'puts', '__stack_chk_fail']);
}

// A C++ DLL with MSVC's names: exports and imports demangled, short in the list, in full in the details.
{
  const p = await open('hello-msvc.dll');
  const fn = (name) => p.functions.find((f) => f.name === name);
  check('MSVC: exported C++ functions', ['geo::scale(…)', 'geo::Point::Point(…)', 'geo::Point::~Point()', 'geo::Point::operator==(…)', 'geo::Box<double>::get()', 'plain'].filter((n) => !fn(n)), []);
  check('MSVC: two overloads, told apart in full', p.functions.filter((f) => f.name === 'geo::scale(…)').map((f) => f.full), ['int __cdecl geo::scale(int, int)', 'double __cdecl geo::scale(double, double)']);
  check('MSVC: imports from the C++ runtime', [fn('operator delete(…)')?.kind, fn('std::_Xlength_error(…)')?.full], ['import', 'void __cdecl std::_Xlength_error(char const *)']);
}

// The HLA64 view of x86-64: a line means what its instruction (or the pair) does, or stays the instruction.
{
  const p = await open('hello-macos', 'x86_64');
  const ctx = p.context();
  const lines = (name) => {
    const fn = p.functions.find((f) => f.name === name);
    const out = [];
    for (let i = fn.first; i < fn.first + fn.count; i++) {
      const line = A.liftX86(p.insn(i), ctx, p.flags[i] & 2 ? p.insn(i + 1) : undefined);
      if (line.fused) i++;
      out.push(line.text);
    }
    return out;
  };
  const main = lines('main');
  check('HLA64: a push is what it does (HLA64\'s own push keeps a frame slot)', main[0], 'rsp -= 8; [rsp] = rbp');
  check('HLA64: lock add is an atomic', main.includes('atomic_add(u64[&counter], r14, seq_cst)'), true);
  check('HLA64: a string', main.includes('rdi = "Hello, x86! sum=%ld step=%ld scaled=%.1f\\n"'), true);
  check('HLA64: calls', ['sum()', 'step()', 'scale4()', 'printf()', 'strcmp()', 'puts()'].filter((c) => !main.includes(c)), []);
  check('HLA64: a compare and its jump', main.some((l) => /^if r14d < 2 \{ goto L[0-9a-f]+ \}$/.test(l)) && main.some((l) => /^if eax != 0 \{ goto L[0-9a-f]+ \}$/.test(l)), true);
  check('HLA64: an 8-bit move stays an instruction', main.includes('mov al, 0x1'), true);
  check('HLA64: a compare with memory stays an instruction', main.includes('cmp rdx, qword ptr [rbp - 0x28]'), true);
  const step = lines('step');
  check('HLA64: an unsigned bound, a table, a jump through it', [step.some((l) => /^if edi >u 7 \{ goto L[0-9a-f]+ \}$/.test(l)), step.includes('rax = i32[rdx + rax * 4]'), step.includes('goto [rax]')], [true, true, true]);
  check('HLA64: a conditional move after a subtraction keeps its flags', step.includes('cmovl rcx, rax'), true);
  check('HLA64: loads and compound assignment', lines('sum').filter((l) => ['rdx = i32[rdi + rcx * 4]', 'rax += rdx', 'rcx += 1'].includes(l)).length, 3);
}
{
  // Single instructions.
  const ctx = { target: () => undefined, data: () => undefined, functionStart: () => -1, importAt: () => undefined };
  const lift = (bytes) => {
    const code = hex(bytes.replace(/ /g, ''));
    return A.liftX86(A.insnOf(decodeX86(code, 0, code.length, 0x1000, 64)), ctx).text;
  };
  for (const [bytes, text] of [
    ['31c0', 'eax = 0'],
    ['4801d8', 'rax += rbx'],
    ['480fafc1', 'rax *= rcx'],
    ['486bc018', 'rax = rax * 0x18'],
    ['488d04b7', 'rax = rdi + rsi * 4'],
    ['0fb607', 'eax = u8[rdi]'],
    ['480fbe07', 'rax = i8[rdi]'],
    ['0fb6c1', 'eax = zext8(ecx)'],
    ['880f', 'u8[rdi] = ecx'],
    ['66890f', 'u16[rdi] = ecx'],
    ['c70705000000', 'u32[rdi] = 5'],
    ['48c707ffffffff', '[rdi] = -1'],
    ['48d3e0', 'rax <<= rcx'],
    ['48c1e803', 'rax >>>= 3'],
    ['48c1f803', 'rax >>= 3'],
    ['48f7d8', 'rax = -rax'],
    ['f20f58c1', 'xmm0 += xmm1'],
    ['f2480f2ac0', 'xmm0 = float(rax)'],
    ['0f57c0', 'xmm0 = 0.0'],
    ['480fc10f', 'xadd qword ptr [rdi], rcx'],
    ['f0480fc10f', 'lock'],
    ['66f0480fc10f', 'rcx = atomic_add(u64[rdi], rcx, seq_cst)'],
    ['66f0480fb10f', 'rax = cas(u64[rdi], rax, rcx, seq_cst)'],
    ['4887 0f', 'rcx = atomic_swap(u64[rdi], rcx, seq_cst)'],
    ['48f7f1', 'div rcx'],
    ['4899', 'cqo'],
    ['e2fe', 'asm "loop 0x1000"'],
    ['ffd0', 'rax()'],
    ['ffe0', 'goto [rax]'],
    ['c3', 'return'],
  ]) check(`HLA64: ${bytes}`, lift(bytes), text);
}

// Windows: PE files built by zig (MinGW).
for (const [file, arch, mode] of [['hello-x64.exe', 'x86_64', 64], ['hello-x86.exe', 'x86', 32], ['hello-x64.dll', 'x86_64', 64]]) {
  const p = await open(file);
  check(`${file}: architecture, platform`, [p.archLabel(), p.platformLabel(), p.mode], [arch, 'Windows Vista+', mode]);
  check(`${file}: the greeting is named (rip-relative or absolute)`, helloRefs(p), 1);
  check(`${file}: imports called through their slots`, ['puts', 'strcmp'].map((name) => [...p.importSlots].filter(([, n]) => n === name).some(([slot]) => p.slotCallers.get(slot)?.length || p.callers.get(p.functions.find((f) => f.raw === name)?.addr)?.length)), [true, true]);
  check(`${file}: the import thunks are functions`, p.functions.filter((f) => f.kind === 'import').map((f) => f.name).includes('puts'), true);
  check(`${file}: everything decodes`, p.counts.find((c) => c.mnemonic === '<unknown>')?.count ?? 0, 0);
}
{
  const p = await open('hello-x64.dll');
  const pe = p.image.pe;
  check('DLL: exports and the switch', [named(p).filter((n) => n.endsWith(':export')).sort(), switches(p).includes('step:8')], [['_CRT_INIT:export', 'atexit:export', 'main:export', 'scale4:export', 'step:export', 'sum:export'], true]);
  check('DLL: headers', [pe.dll, pe.is64, pe.machineName, pe.subsystemName, pe.dllName, pe.libraries.includes('KERNEL32.dll')], [true, true, 'x86-64', 'Windows GUI', 'hello-x64.dll', true]);
  check('DLL: the unwind table lists the functions', pe.functionStarts.length > 20 && p.functions.some((f) => f.name === 'step'), true);
}
{
  const p = await open('hello-x86.exe');
  check('i386 PE: absolute addresses in immediates', p.absolute, true);
}

done('x86');
