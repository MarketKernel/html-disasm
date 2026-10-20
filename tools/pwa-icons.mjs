/**
 * Draws assets/icon.svg into the PNG icons the PWA needs, in assets/pwa/:
 * 192 and 512 pixels as the icon is, with its rounded corners; a maskable 512
 * and Apple's 180, where the system cuts the shape itself, as a full square
 * (the drawing keeps within the maskable safe zone, the middle 80%).
 *
 *   node tools/pwa-icons.mjs        after a change to assets/icon.svg
 *
 * The PNGs are committed: the build only copies them, and needs no Chrome.
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { launch } from './chrome.mjs';
import { root } from './load.mjs';

const svg = (await readFile(join(root, 'assets', 'icon.svg'), 'utf8')).trim();
const ROUNDED = /<rect x="2" y="2" width="60" height="60" rx="15"/;
if (!ROUNDED.test(svg)) throw new Error('assets/icon.svg: its background rect is not where this tool expects it');
const square = svg.replace(ROUNDED, '<rect width="64" height="64"');

const ICONS = [
  ['icon-192.png', 192, svg],
  ['icon-512.png', 512, svg],
  ['icon-maskable-512.png', 512, square],
  ['apple-touch-icon.png', 180, square],
];

const browser = await launch();
if (!browser) {
  console.error('No Chrome found — set CHROME=/path/to/chrome.');
  process.exit(1);
}
const out = join(root, 'assets', 'pwa');
await mkdir(out, { recursive: true });
try {
  await browser.send('Emulation.setDefaultBackgroundColorOverride', { color: { r: 0, g: 0, b: 0, a: 0 } });
  for (const [name, size, source] of ICONS) {
    await browser.send('Emulation.setDeviceMetricsOverride', { width: size, height: size, deviceScaleFactor: 1, mobile: false });
    const html = `<!doctype html><style>html,body{margin:0;background:transparent}svg{display:block;width:${size}px;height:${size}px}</style>${source}`;
    await browser.send('Page.navigate', { url: `data:text/html;base64,${Buffer.from(html).toString('base64')}` });
    await browser.until('document.readyState === "complete" && !!document.querySelector("svg")');
    const { data } = await browser.send('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: 0, width: size, height: size, scale: 1 } });
    await writeFile(join(out, name), Buffer.from(data, 'base64'));
    console.log(`assets/pwa/${name} ${size}×${size}`);
  }
} finally {
  await browser.close();
}
