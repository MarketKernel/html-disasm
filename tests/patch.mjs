/**
 * Patching a macOS program: new bytes at an address, then an ad hoc
 * signature computed afresh. On a Mac the result is checked the strict way —
 * `codesign --verify` accepts it and the patched program runs and does what
 * the new instructions say; elsewhere only the structure is checked.
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const { check, done } = checker();
const M = await load('core/macho', 'core/patch', 'core/arm64/decode', 'core/arm64/types');
const mac = process.platform === 'darwin' && spawnSync('codesign', ['--help']).error === undefined;
const dir = mkdtempSync(join(tmpdir(), 'patch-test-'));

/** Patches `main` of a program to return `code` at once, signs it again, and runs it. */
async function patchAndRun(source, code) {
  const file = new Uint8Array(readFileSync(source));
  const image = M.parseMachO(file);
  const main = image.symbols.find((s) => s.name === '_main');
  const words = [0x52800000 | (code << 5), 0xd65f03c0]; // mov w0, #code; ret
  const bytes = new Uint8Array(new Uint32Array(words).buffer);
  const offset = M.fileOffsetOf(image, main.addr, 8);
  const patch = { addr: main.addr, offset, before: file.slice(offset, offset + 8), after: bytes };
  M.applyPatch(file, patch);
  const result = await M.resignFile(file, image);
  const out = join(dir, `patched-${code}`);
  writeFileSync(out, file);
  chmodSync(out, 0o755);
  const again = M.parseMachO(file);
  return { image, again, result, out, patch, file };
}

const hello = await patchAndRun(join(root, 'tests', 'fixtures', 'hello'), 42);
check('the patch is in the file', [...hello.file.subarray(hello.patch.offset, hello.patch.offset + 8)], [...hello.patch.after]);
check('it decodes as written', M.formatInsn(M.decode(new DataView(hello.patch.after.buffer).getUint32(0, true), hello.patch.addr)), 'mov w0, #0x2a');
check('the old signature was ad hoc', hello.result.was, 'adhoc');
check('signed ad hoc again, with its identifier', [hello.again.signature?.flags & 2, hello.again.signature?.identifier], [2, hello.image.signature?.identifier]);
check('undo restores the bytes', (() => {
  const copy = hello.file.slice();
  M.applyPatch(copy, hello.patch, true);
  return [...copy.subarray(hello.patch.offset, hello.patch.offset + 8)];
})(), [...hello.patch.before]);

if (mac) {
  const verify = spawnSync('codesign', ['--verify', '--strict', hello.out], { encoding: 'utf8' });
  check('codesign --verify accepts the new signature', [verify.status, verify.stderr.trim()], [0, '']);
  const run = spawnSync(hello.out, [], { encoding: 'utf8' });
  check('the patched program runs and returns 42', run.status, 42);
  // A universal file: the arm64 slice is patched and signed, the x86_64 one is left alone.
  const fat = join(dir, 'fat');
  const built = spawnSync('clang', ['-O1', '-arch', 'arm64', '-arch', 'x86_64', '-o', fat, join(root, 'tests', 'fixtures', 'hello.c')], { encoding: 'utf8' });
  if (built.status === 0) {
    const universal = await patchAndRun(fat, 7);
    check('universal: the arm64 slice', [universal.image.arches.length, universal.image.sliceOffset > 0], [2, true]);
    // The linker signs only the arm64 slice; the x86_64 one stays unsigned, as clang left it.
    check('universal: the arm64 slice verified', spawnSync('codesign', ['--verify', '--strict', '--arch', 'arm64', universal.out]).status, 0);
    check('universal: runs and returns 7', spawnSync(universal.out).status, 7);
  } else console.log('clang could not build a universal program; skipped');
} else console.log('Not a Mac: the patched programs were not run.');

rmSync(dir, { recursive: true, force: true });
done('patch');

