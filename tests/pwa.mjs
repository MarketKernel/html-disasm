/**
 * The PWA of build/pages/ in headless Chrome, from a local server: the service
 * worker takes the page over, Chrome reads the manifest and finds the app
 * installable, the page opens a program with the server gone, and a new
 * deploy comes in by itself. Needs `npm run build` first and a local Chrome
 * (CHROME=/path/to/chrome to pick one); without Chrome it is skipped.
 */
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { launch } from '../tools/chrome.mjs';
import { checker, root } from '../tools/load.mjs';

const PAGES = join(root, 'build', 'pages');
const PROGRAM = join(root, 'tests', 'fixtures', 'hello');

if (!existsSync(join(PAGES, 'index.html'))) {
  console.error('build/pages/ is missing: run `npm run build` first');
  process.exit(1);
}

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.svg': 'image/svg+xml' };
let down = false;
/** Set, the server plays the next deploy: another cache name in sw.js, a mark in the page. */
let next = false;

const server = createServer(async (req, res) => {
  if (down) return req.socket.destroy();
  const path = new URL(req.url, 'http://localhost').pathname;
  const name = normalize(path === '/' ? 'index.html' : path.slice(1));
  if (name.startsWith('..')) return res.writeHead(404).end();
  try {
    let body = await readFile(join(PAGES, name));
    if (next && name === 'sw.js') body = body.toString().replace(/const CACHE = 'disasm-[^']*'/, "const CACHE = 'disasm-next'");
    if (next && name === 'index.html') body = body.toString().replace('</head>', '<meta name="deploy" content="next">\n</head>');
    res.writeHead(200, { 'content-type': TYPES[extname(name)] ?? 'application/octet-stream', 'cache-control': 'no-cache' }).end(body);
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const url = `http://127.0.0.1:${server.address().port}/`;

const browser = await launch();
if (!browser) {
  server.close();
  console.log('No Chrome found — set CHROME=/path/to/chrome. Skipping the PWA test.');
  process.exit(0);
}

const { check, done } = checker();
const b = browser;

try {
  await b.open(url);
  check('the page knows it is the PWA', await b.evaluate('document.querySelector("meta[name=service-worker]")?.content'), 'sw.js');
  check('still no network for the page', await b.evaluate('document.querySelector("meta[http-equiv=Content-Security-Policy]").content.includes("connect-src \'none\'")'), true);
  check('service worker in control', await b.until('navigator.serviceWorker.controller !== null'), true);

  const manifest = await b.send('Page.getAppManifest');
  check('manifest parsed', manifest.errors, []);
  check('manifest name', JSON.parse(manifest.data).name, 'Disassembler');
  const { installabilityErrors } = await b.send('Page.getInstallabilityErrors');
  check('installable', installabilityErrors, []);

  // Offline: the page and a program from disk.
  down = true;
  await b.open(url);
  check('opens offline', await b.evaluate('!document.getElementById("start").hidden'), true);
  await b.setFile('#file-input', PROGRAM);
  await b.until('!document.getElementById("workspace").hidden && document.querySelectorAll("#listing-rows .row").length > 10');
  check('reads a program offline', await b.evaluate('document.getElementById("file-name").textContent'), 'hello');
  down = false;

  // A new deploy: the browser finds the new worker, which takes over and drops the old cache.
  next = true;
  await b.evaluate('navigator.serviceWorker.getRegistration().then((registration) => registration.update())');
  await b.until('caches.keys().then((keys) => keys.length === 1 && keys[0] === "disasm-next")');
  check('the new deploy replaces the old cache', await b.evaluate('caches.keys()'), ['disasm-next']);
  down = true;
  await b.open(url);
  check('the next launch is the new deploy, offline too', await b.evaluate('document.querySelector("meta[name=deploy]")?.content ?? null'), 'next');
  down = false;

  check('no errors on the page', b.errors, []);
} finally {
  await b.close();
  server.close();
}
done('pwa');
