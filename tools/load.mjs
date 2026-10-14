/**
 * Compiles a few src/ modules for Node, so the tests exercise the very code the
 * page runs. JSON imports (the instruction catalogue, the HLA64 words) are
 * bundled in as they are in the page.
 */
import { build } from 'esbuild';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { textPlugin } from './text-plugin.mjs';

export const root = dirname(dirname(fileURLToPath(import.meta.url)));

export async function load(...modules) {
  const result = await build({
    stdin: {
      contents: modules.map((name) => `export * from './src/${name}';`).join('\n'),
      resolveDir: root,
      loader: 'ts',
    },
    bundle: true,
    format: 'cjs',
    platform: 'node',
    target: 'node20',
    plugins: [textPlugin],
    write: false,
    logLevel: 'silent',
  });
  const dir = await mkdtemp(join(tmpdir(), 'disasm-test-'));
  const file = join(dir, 'bundle.cjs');
  await writeFile(file, result.outputFiles[0].text);
  try {
    return createRequire(import.meta.url)(file);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export function checker() {
  let passed = 0;
  let failed = 0;
  const check = (name, actual, expected) => {
    // BigInts (64-bit immediates) compare as their decimal text.
    const json = (value) => JSON.stringify(value, (_, v) => (typeof v === 'bigint' ? `${v}n` : v));
    const a = json(actual);
    const b = json(expected);
    if (a === b) passed += 1;
    else {
      failed += 1;
      console.error(`FAIL  ${name}\n  expected: ${b}\n  actual:   ${a}`);
    }
  };
  const done = (label) => {
    console.log(`${label}: ${passed} passed, ${failed} failed`);
    if (failed) process.exit(1);
  };
  return { check, done };
}
