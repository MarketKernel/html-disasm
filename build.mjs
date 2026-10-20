/**
 * Bundles src/ into ONE self-contained build/disassembler.html.
 *
 * Styles, the instruction catalogue, the HLA64 words, the icon and the
 * compiled TypeScript are all inlined, so the result opens from a file:// URL
 * with no network access and no sibling files. The code — most of it the
 * catalogues' text — and the core's WebAssembly module go in as one deflated
 * stream, written as text seven bits to a character. A few lines in the
 * template decode and inflate it, hand the module's bytes to the code and run it.
 *
 * Beside it goes build/pages/: the same page as an installable PWA for GitHub
 * Pages — a manifest, icons and a service worker that keeps it offline.
 *
 * The version is package.json's and nowhere else: the page shows it, the
 * PWA's cache is named after it.
 *
 *   node build.mjs           build once
 *   node build.mjs --watch   rebuild on every change under src/ and assets/
 */
import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateRawSync } from 'node:zlib';
import { textPlugin } from './tools/text-plugin.mjs';

const root = dirname(fileURLToPath(import.meta.url));
const at = (...parts) => join(root, ...parts);
const watch = process.argv.includes('--watch');
const outFile = at('build', 'disassembler.html');

/**
 * package.json's version as the page shows it: the same for a build of the
 * commit tagged v<version>, with the commit added for any other —
 * 0.1.0+1a2b3c4 — so a page built from main is not taken for the release.
 */
async function readRelease() {
  const { version } = JSON.parse(await readFile(at('package.json'), 'utf8'));
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`package.json: the version must be x.y.z, not ${version}`);
  const git = (...args) => {
    try {
      return execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch {
      return '';
    }
  };
  const tagged = process.env.RELEASE_TAG === `v${version}` || git('tag', '--points-at', 'HEAD').split('\n').includes(`v${version}`);
  const commit = tagged ? '' : git('rev-parse', '--short', 'HEAD');
  return { version, label: commit ? `${version}+${commit}` : version };
}

/** The whole point of the build: nothing may be fetched at runtime. */
function assertSelfContained(html) {
  const offenders = [
    [/<script[^>]+\ssrc=/i, '<script src=…>'],
    [/<link[^>]+href=["'](?!data:)/i, '<link href=…>'],
    [/@import\s+(url\()?["']?(?!data:)/i, '@import'],
    [/url\(\s*["']?https?:/i, 'url(http…)'],
  ];
  for (const [pattern, name] of offenders) {
    if (pattern.test(html)) throw new Error(`An external reference is left in the file: ${name}`);
  }
  if (!html.includes('http-equiv="Content-Security-Policy"')) throw new Error('The Content-Security-Policy meta tag is missing');
}

/** Under assets/; each goes to build/pages/ under its own name. */
const PWA_ICONS = ['icon.svg', 'pwa/icon-192.png', 'pwa/icon-512.png', 'pwa/icon-maskable-512.png', 'pwa/apple-touch-icon.png'];

/**
 * The page's CSP forbids every fetch; the installed app needs its manifest, its
 * service worker and its icons, all from its own origin. connect-src stays 'none',
 * so the page itself still reaches nothing.
 */
function allowPwa(html) {
  const pattern = /(http-equiv="Content-Security-Policy" content=")([^"]*)/;
  if (!pattern.test(html)) throw new Error('The Content-Security-Policy meta tag is missing');
  return html.replace(pattern, (_, attr, policy) => {
    const directives = new Map(policy.split(';').map((d) => d.trim().split(/\s+/)).map(([name, ...sources]) => [name, sources]));
    if (!directives.has('img-src')) throw new Error('The Content-Security-Policy has no img-src');
    directives.get('img-src').push("'self'");
    directives.set('manifest-src', ["'self'"]);
    directives.set('worker-src', ["'self'"]);
    return attr + [...directives].map(([name, sources]) => [name, ...sources].join(' ')).join('; ');
  });
}

/**
 * build/pages/: the page plus what makes it installable. Every path is
 * relative, so it works under a project site's /<repo>/ prefix.
 */
async function buildPages(html, release) {
  const dir = at('build', 'pages');
  const head = [
    '<link rel="manifest" href="manifest.webmanifest">',
    '<link rel="apple-touch-icon" href="apple-touch-icon.png">',
    '<meta name="theme-color" content="#f6f5f2" media="(prefers-color-scheme: light)">',
    '<meta name="theme-color" content="#121214" media="(prefers-color-scheme: dark)">',
    '<meta name="apple-mobile-web-app-capable" content="yes">',
    '<meta name="apple-mobile-web-app-status-bar-style" content="default">',
    // The page registers the worker itself (src/app/pwa.ts): this is how it knows it is the PWA.
    '<meta name="service-worker" content="sw.js">',
  ].join('\n');
  const page = allowPwa(html).replace('</head>', () => `${head}\n</head>`);
  // A deploy between two releases changes the page, not the version: the hash tells them apart.
  const cache = `${release.version}-${createHash('sha256').update(page).digest('hex').slice(0, 12)}`;

  const manifest = {
    name: 'Disassembler',
    short_name: 'Disassembler',
    description: 'An Arm, x86, WebAssembly, .NET and Java disassembler that works offline',
    id: './',
    start_url: './',
    scope: './',
    display: 'standalone',
    background_color: '#f6f5f2',
    theme_color: '#5446d8',
    icons: [
      { src: 'icon.svg', sizes: 'any', type: 'image/svg+xml' },
      { src: 'icon-192.png', sizes: '192x192', type: 'image/png' },
      { src: 'icon-512.png', sizes: '512x512', type: 'image/png' },
      { src: 'icon-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
    ],
  };

  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  const worker = (await readFile(at('src/pwa/sw.js'), 'utf8')).replaceAll('__CACHE__', cache);
  await Promise.all([
    writeFile(join(dir, 'index.html'), page, 'utf8'),
    writeFile(join(dir, 'sw.js'), worker, 'utf8'),
    writeFile(join(dir, 'manifest.webmanifest'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8'),
    // Without it Pages runs the files through Jekyll, which is only wasted time here.
    writeFile(join(dir, '.nojekyll'), '', 'utf8'),
    ...PWA_ICONS.map((path) => copyFile(at('assets', path), join(dir, basename(path)))),
  ]);
  console.log(`build/pages/ — PWA for GitHub Pages (cache ${cache})`);
}

/**
 * The characters that may not stand for themselves in the page's code block:
 * NUL and CR, which the HTML parser replaces, LF, so that the block is one line
 * no editor changes, and `<`, which could end it.
 */
const ESCAPED = [0, 10, 13, 60];

/**
 * Bytes as text, seven bits to a character — base64 carries six in a byte,
 * this seven. A group of seven bits is the character of its value, unless that
 * is one of ESCAPED; then the group and the one after it go in one two-byte
 * character, 128 + its index in ESCAPED × 128 + the next group. The loader in
 * template.html reads it back.
 */
function sevenBit(bytes) {
  const groups = [];
  let acc = 0;
  let bits = 0;
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 7) {
      bits -= 7;
      groups.push((acc >> bits) & 127);
    }
    acc &= (1 << bits) - 1;
  }
  if (bits) groups.push((acc << (7 - bits)) & 127);
  const codes = [];
  for (let i = 0; i < groups.length; i++) {
    const escaped = ESCAPED.indexOf(groups[i]);
    codes.push(escaped < 0 ? groups[i] : 128 + escaped * 128 + (groups[++i] ?? 0));
  }
  let text = '';
  for (let i = 0; i < codes.length; i += 8192) text += String.fromCharCode(...codes.slice(i, i + 8192));
  return text;
}

/**
 * The core's module rides in the page's stream as bytes, not inside the code as base64 (which
 * deflate cannot shrink back): the code finds it where the template's loader leaves it.
 */
const coreFromPage = {
  name: 'core-from-page',
  setup(build) {
    build.onResolve({ filter: /core\.wasm$/ }, () => ({ path: 'core.wasm', namespace: 'core-from-page' }));
    build.onLoad({ filter: /.*/, namespace: 'core-from-page' }, () => ({ contents: 'export default globalThis.__DISASM_CORE__;', loader: 'js' }));
  },
};

async function bundle(release) {
  const result = await build({
    entryPoints: [at('src/app/main.ts')],
    bundle: true,
    format: 'iife',
    target: ['es2022'],
    platform: 'browser',
    minify: !watch,
    sourcemap: false,
    legalComments: 'none',
    charset: 'utf8',
    define: { __APP_VERSION__: JSON.stringify(release.label) },
    plugins: [textPlugin, coreFromPage],
    write: false,
  });
  const output = result.outputFiles[0];
  if (!output) throw new Error('esbuild returned an empty result');
  return output.text;
}

async function buildOnce() {
  const release = await readRelease();
  const [template, styles, icon, appJs, core] = await Promise.all([
    readFile(at('src/app/template.html'), 'utf8'),
    readFile(at('src/app/styles.css'), 'utf8'),
    readFile(at('assets/icon.svg'), 'utf8'),
    bundle(release),
    readFile(at('target', 'core.wasm')),
  ]);
  const iconUri = `data:image/svg+xml;base64,${Buffer.from(icon.trim(), 'utf8').toString('base64')}`;
  // The name makes the code a file of its own in the browser's developer tools.
  // The stream: the code's length (u32), the code, the module.
  const code = Buffer.from(`${appJs}\n//# sourceURL=disassembler.js\n`, 'utf8');
  const length = Buffer.alloc(4);
  length.writeUInt32LE(code.length);
  const deflated = deflateRawSync(Buffer.concat([length, code, core]), { level: 9 });
  const packed = sevenBit(deflated);
  const html = template
    .replace('/*__STYLES__*/', () => styles)
    .replace('__APP_LENGTH__', () => String(deflated.length))
    .replace('__APP__', () => packed)
    .replaceAll('__ICON__', () => iconUri);
  assertSelfContained(html);
  await mkdir(at('build'), { recursive: true });
  await writeFile(outFile, html, 'utf8');
  const kb = (n) => (n / 1024).toFixed(1);
  console.log(`build/disassembler.html ${release.label} — ${kb(Buffer.byteLength(html, 'utf8'))} KB (code ${kb(Buffer.byteLength(appJs, 'utf8'))} KB, core ${kb(core.length)} KB, ${kb(Buffer.byteLength(packed, 'utf8'))} KB packed; styles ${kb(styles.length)} KB)`);
  await buildPages(html, release);
}

await buildOnce();

if (watch) {
  const { watch: watchDir } = await import('node:fs');
  let pending = null;
  for (const dir of ['src', 'assets']) {
    watchDir(at(dir), { recursive: true }, () => {
      clearTimeout(pending);
      pending = setTimeout(() => buildOnce().catch((error) => console.error(error.message)), 120);
    });
  }
  console.log('watching src/ and assets/ …');
}
