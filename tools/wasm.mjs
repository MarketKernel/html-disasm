/**
 * Builds the Rust core (crates/) into the WebAssembly module the page and the
 * tests load: target/core.wasm. Cargo builds crates/wasm for
 * wasm32-unknown-unknown; wasm-opt (Binaryen), when it is on the PATH, makes
 * the module smaller and faster. The module must import nothing — the core
 * asks nothing of whatever runs it — and the build checks that it does not.
 *
 *   node tools/wasm.mjs           build (release)
 *   node tools/wasm.mjs --quiet   the same, printing only errors
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { copyFileSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const quiet = process.argv.includes('--quiet');
const built = join(root, 'target', 'wasm32-unknown-unknown', 'release', 'disasm_wasm.wasm');
const out = join(root, 'target', 'core.wasm');

execFileSync('cargo', ['build', '--release', '-p', 'disasm-wasm', '--target', 'wasm32-unknown-unknown', ...(quiet ? ['--quiet'] : [])], { cwd: root, stdio: 'inherit' });

const opt = spawnSync('wasm-opt', ['--version'], { encoding: 'utf8' });
if (opt.status === 0) {
  execFileSync('wasm-opt', ['-O3', '--enable-bulk-memory', '--enable-nontrapping-float-to-int', '--enable-sign-ext', '--enable-mutable-globals', built, '-o', out], { stdio: 'inherit' });
} else {
  if (!quiet) console.log('wasm-opt is not on the PATH: the module goes in as Cargo built it');
  copyFileSync(built, out);
}

// The core imports nothing: a host only instantiates it.
const module = new WebAssembly.Module(readFileSync(out));
const imports = WebAssembly.Module.imports(module);
if (imports.length) throw new Error(`target/core.wasm imports ${imports.map((i) => `${i.module}.${i.name}`).join(', ')}: the core must ask nothing of its host`);
if (!quiet) console.log(`target/core.wasm: ${(statSync(out).size / 1024).toFixed(0)} KB, no imports`);
