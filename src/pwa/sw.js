/**
 * Service worker of the GitHub Pages build (build/pages/): keeps the
 * disassembler working offline once it has been opened.
 *
 * build.mjs writes a hash of the page into CACHE, so every deploy changes this
 * file's bytes and the browser installs the new worker. It takes over at once:
 * the page holds nothing a new version could lose — the program is read from
 * the person's disk and nothing is saved — so the window already open keeps
 * the code it runs, and the next launch or reload is the new version.
 */
const CACHE = 'disasm-__CACHE__';
const SHELL = ['./', 'manifest.webmanifest', 'icon.svg', 'icon-192.png', 'icon-512.png', 'icon-maskable-512.png', 'apple-touch-icon.png'];

self.addEventListener('install', (event) => {
  // Past the HTTP cache: a page Pages served a few minutes ago may be the previous deploy's.
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(SHELL.map((url) => new Request(url, { cache: 'reload' }))))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((key) => key.startsWith('disasm-') && key !== CACHE).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;
  const cached = (key, options) => caches.open(CACHE).then((cache) => cache.match(key, options));
  // Any navigation inside the scope is the disassembler itself.
  if (request.mode === 'navigate') {
    event.respondWith(cached('./').then((page) => page ?? fetch(request)));
    return;
  }
  // The page fetches nothing itself (its CSP has connect-src 'none'): what comes here is
  // the manifest and the icons, all in the shell.
  event.respondWith(cached(request, { ignoreSearch: true }).then((file) => file ?? fetch(request)));
});
