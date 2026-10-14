/**
 * Screenshots of the main screens, to check the layout by eye: the start
 * page, the listing in assembly and in HLA64, the details panel, the
 * statistics, the reference, the Mach-O or ELF page, dark mode and a phone.
 *
 *   node tools/shots.mjs [dir] [program]
 *
 * Builds first. The program defaults to tests/fixtures/hello (or $PROGRAM).
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { launch } from './chrome.mjs';
import { root } from './load.mjs';

const dir = resolve(process.argv[2] ?? 'shots');
const program = resolve(process.argv[3] ?? process.env.PROGRAM ?? join(root, 'tests', 'fixtures', 'hello'));
mkdirSync(dir, { recursive: true });
if (spawnSync(process.execPath, ['build.mjs'], { cwd: root, stdio: 'inherit' }).status !== 0) process.exit(1);

const browser = await launch();
if (!browser) {
  console.log('No Chrome found — set CHROME=/path/to/chrome.');
  process.exit(0);
}
const url = pathToFileURL(join(root, 'build', 'disassembler.html')).href;
try {
  await browser.viewport(1440, 900);
  await browser.theme('light');
  await browser.open(url);
  await browser.shot(join(dir, '01-start.png'));
  await browser.setFile('#file-input', program);
  // A package (.apk, .ipa) with more than one program asks which one: the first is taken.
  await browser.until('(!document.getElementById("workspace").hidden || !document.getElementById("picker").hidden) && document.getElementById("progress").hidden', 120000);
  if (await browser.evaluate('!document.getElementById("picker").hidden')) {
    await browser.shot(join(dir, '00-picker.png'));
    await browser.evaluate('document.querySelector("#picker-list .picker-item:not(:disabled)").click()');
    await browser.until('!document.getElementById("workspace").hidden && document.getElementById("progress").hidden', 120000);
  }
  await browser.until('document.querySelectorAll("#listing-rows .row").length > 5');
  await browser.evaluate('document.querySelector("#listing-rows .row:not(.fn):not(.gap):not(.label):not(.section)")?.click()');
  await browser.shot(join(dir, '02-listing-asm.png'));
  // 32-bit Arm code has no HLA64 view.
  if (await browser.evaluate('!document.querySelector("[data-mode=hla]").disabled')) {
    await browser.press('h');
    await browser.until('document.querySelector("[data-mode=hla]").getAttribute("aria-checked") === "true"');
    await browser.shot(join(dir, '03-listing-hla.png'));
  }
  await browser.theme('dark');
  await browser.shot(join(dir, '04-listing-dark.png'));
  await browser.theme('light');
  await browser.evaluate('document.querySelector("[data-view=stats]").click()');
  await browser.shot(join(dir, '05-stats.png'));
  await browser.evaluate('document.querySelector("[data-view=reference]").click()');
  await browser.shot(join(dir, '06-reference-words.png'));
  await browser.evaluate('document.querySelector("#stats-bars [data-mn]").click()');
  await browser.shot(join(dir, '07-reference-mnemonic.png'));
  await browser.evaluate('document.querySelector("[data-view=overview]").click()');
  await browser.shot(join(dir, '08-container.png'));
  await browser.evaluate('document.querySelector("[data-view=strings]").click()');
  await browser.shot(join(dir, '09-strings.png'));
  await browser.evaluate('document.querySelector("[data-view=imports]").click()');
  await browser.shot(join(dir, '10-imports.png'));
  await browser.evaluate('document.querySelector("[data-view=listing]").click()');
  await browser.press('k', 'KeyK', 4);
  await browser.type('main');
  await browser.shot(join(dir, '11-search.png'));
  await browser.press('Escape');
  await browser.viewport(390, 844, true);
  await browser.shot(join(dir, '12-phone.png'));
  if (browser.errors.length) console.log(`page errors:\n${browser.errors.join('\n')}`);
  console.log(`screenshots in ${dir}`);
} finally {
  await browser.close();
}
