/**
 * Drives the built page in headless Chrome: opening tests/fixtures/hello,
 * the listing in assembly and HLA64, following a call and coming back, the
 * search box, the statistics, the reference, the Mach-O page — and a file
 * that is not a program; then tests/fixtures/hello.wasm, the same program as a
 * WebAssembly module; then as a .NET assembly (C#, tests/fixtures/dotnet); then as a JAR (Java,
 * tests/fixtures/jvm); then the Android build of it, from an APK (armeabi-v7a)
 * and as a library (arm64-v8a); then x86: the x86_64 slice of a universal
 * macOS program and an i386 Android library. Needs `npm run build` first and a local Chrome
 * (CHROME=/path/to/chrome to pick one); without Chrome it is skipped.
 *
 * `--shots DIR` also saves a few screenshots into DIR.
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { launch } from '../tools/chrome.mjs';
import { checker, root } from '../tools/load.mjs';

const APP = join(root, 'build', 'disassembler.html');
const PROGRAM = join(root, 'tests', 'fixtures', 'hello');
const shotsAt = process.argv.indexOf('--shots');
const SHOTS = shotsAt > 0 ? process.argv[shotsAt + 1] : null;
if (SHOTS) mkdirSync(SHOTS, { recursive: true });

if (!existsSync(APP)) {
  console.error('build/disassembler.html is missing: run `npm run build` first');
  process.exit(1);
}
const browser = await launch();
if (!browser) {
  console.log('No Chrome found — set CHROME=/path/to/chrome. Skipping the browser tests.');
  process.exit(0);
}

const { check, done } = checker();
const b = browser;
const text = (selector) => b.evaluate(`document.querySelector(${JSON.stringify(selector)})?.textContent ?? null`);
const META = process.platform === 'darwin' ? 4 : 2;

try {
  await b.viewport(1440, 900);
  await b.open(pathToFileURL(APP).href);
  check('start page', await b.evaluate('!document.getElementById("start").hidden && document.getElementById("workspace").hidden'), true);
  check('no network allowed', await b.evaluate('document.querySelector("meta[http-equiv=Content-Security-Policy]").content.includes("connect-src \'none\'")'), true);

  // Not a program.
  await b.setFile('#file-input', join(root, 'tests', 'fixtures', 'hello.c'));
  await b.until('document.getElementById("start-error").textContent.length > 0');
  check('a C file is refused', await text('#start-error'), 'Not a Mach-O program (no 0xfeedfacf signature).');

  // The program.
  await b.setFile('#file-input', PROGRAM);
  await b.until('!document.getElementById("workspace").hidden && document.getElementById("progress").hidden');
  await b.until('document.querySelectorAll("#listing-rows .row").length > 10');
  check('file name', await text('#file-name'), 'hello');
  check('arch and platform', [await text('#file-arch'), await text('#file-platform')], ['arm64', 'macOS 26.0+']);
  check('opens at main', (await text('#crumb')).startsWith('main'), true);
  check('main header selected', await b.evaluate('document.querySelector("#listing-rows .row.is-selected")?.classList.contains("fn")'), true);
  check('function list', await b.evaluate('[...document.querySelectorAll("#fn-list .fn-name")].map((n) => n.textContent).includes("average")'), true);
  check('inspector shows the function', (await text('#inspector')).includes('Called from'), true);

  // Select an instruction: the inspector explains it.
  await b.evaluate('[...document.querySelectorAll("#listing-rows .row")].find((r) => r.querySelector(".r-mn")?.textContent === "bl").click()');
  await b.until('document.querySelector("#inspector .insn-mn")?.textContent === "bl"');
  check('bl explained', (await text('#inspector .insn-summary')).length > 3, true);
  check('bl has HLA64', (await text('#inspector')).includes('In HLA64'), true);

  // Follow a call by clicking its name, then come back.
  await b.until('document.getElementById("crumb").textContent.includes("+")');
  const before = await text('#crumb');
  await b.evaluate('[...document.querySelectorAll("#listing-rows .t-name")].find((n) => n.textContent === "sum").click()');
  await b.until('document.getElementById("crumb").textContent.startsWith("sum")');
  check('followed the call', (await text('#crumb')).startsWith('sum'), true);
  await b.press('ArrowLeft', 'ArrowLeft', 1);
  await b.until(`document.getElementById("crumb").textContent === ${JSON.stringify(before)}`);
  check('back', await text('#crumb'), before);
  if (SHOTS) await b.shot(join(SHOTS, 'asm.png'));

  // HLA64.
  await b.evaluate('document.getElementById("listing").focus()');
  await b.press('h');
  await b.until('document.getElementById("listing-rows").textContent.includes("fn main() {")');
  const hla = await b.evaluate('document.getElementById("listing-rows").textContent');
  check('HLA64: fn header', hla.includes('fn main() {'), true);
  check('HLA64: a call', hla.includes('printf()') || hla.includes('sum()'), true);
  check('HLA64: the atomic', /atomic_add\(u64\[x\d+\], x\d+, release\)/.test(hla), true);
  if (SHOTS) await b.shot(join(SHOTS, 'hla.png'));
  await b.press('a');
  await b.until('document.querySelector("#listing-rows .r-mn") !== null');

  // Keys move the selection.
  await b.evaluate('document.getElementById("listing").focus()');
  const frames = () => b.evaluate('new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))');
  await frames();
  const selectedBefore = await b.evaluate('document.querySelector("#listing-rows .row.is-selected")?.dataset.row');
  await b.press('ArrowDown');
  await b.press('ArrowDown');
  // Two rows down, or three when one of them is the gap before a function header.
  await b.until(`Number(document.querySelector("#listing-rows .row.is-selected")?.dataset.row) >= ${Number(selectedBefore) + 2}`);
  check('arrow keys move', Number(await b.evaluate('document.querySelector("#listing-rows .row.is-selected")?.dataset.row')) - Number(selectedBefore) <= 3, true);

  // The side panels resize: the arrow keys on a focused border, back to the usual width on a double-click.
  const sidebarWidth = () => b.evaluate('document.getElementById("sidebar").getBoundingClientRect().width');
  const usual = await sidebarWidth();
  await b.evaluate('document.getElementById("resize-sidebar").focus()');
  await b.press('ArrowRight', 'ArrowRight', 8);
  await b.until(`document.getElementById("sidebar").getBoundingClientRect().width === ${usual + 64}`);
  check('the function list widens', (await sidebarWidth()) - usual, 64);
  check('the width is remembered', await b.evaluate('JSON.parse(localStorage.getItem("arm64-disassembler.settings")).sidebarWidth'), usual + 64);
  await b.evaluate('document.getElementById("resize-inspector").focus()');
  await b.press('ArrowLeft');
  await b.until('document.getElementById("inspector").getBoundingClientRect().width === 386');
  check('the details panel widens', await b.evaluate('document.getElementById("inspector").getBoundingClientRect().width'), 386);
  await b.drag('#resize-sidebar', 150);
  check('dragging the border', (await sidebarWidth()) - usual, 214);
  await b.drag('#resize-sidebar', -2000);
  check('not narrower than 180 pixels', await sidebarWidth(), 180);
  await b.evaluate('document.getElementById("resize-sidebar").dispatchEvent(new MouseEvent("dblclick", { bubbles: true }))');
  await b.evaluate('document.getElementById("resize-inspector").dispatchEvent(new MouseEvent("dblclick", { bubbles: true }))');
  check('a double-click brings the usual widths back', [await sidebarWidth(), await b.evaluate('document.getElementById("inspector").getBoundingClientRect().width')], [usual, 370]);
  await b.evaluate('document.getElementById("listing").focus()');
  // Search.
  await b.press('k', 'KeyK', META);
  await b.until('!document.getElementById("palette").hidden');
  await b.type('avera');
  await b.until('document.querySelectorAll("#palette-results .palette-item").length > 0');
  await b.press('Enter');
  await b.until('document.getElementById("crumb").textContent.startsWith("average")');
  check('search goes to a function', (await text('#crumb')).startsWith('average'), true);

  // Statistics.
  await b.evaluate('document.querySelector("#tabs [data-view=stats]").click()');
  const bars = await b.evaluate('[...document.querySelectorAll("#stats-bars .bar-row:not(.head)")].map((r) => [r.dataset.mn, Number(r.querySelector(".bar-count").textContent.replace(/,/g, ""))])');
  check('statistics: one row per mnemonic, most frequent first', bars.length > 10 && bars.every((row, i) => i === 0 || bars[i - 1][1] >= row[1]), true);
  check('statistics add up', bars.reduce((n, row) => n + row[1], 0), Number((await text('.tile-value')).replace(/,/g, '')));
  await b.evaluate('document.getElementById("stats-join").click()');
  check('joined conditions', await b.evaluate('[...document.querySelectorAll("#stats-bars [data-mn]")].some((r) => r.dataset.mn === "b.cond") || ![...document.querySelectorAll("#stats-bars [data-mn]")].some((r) => r.dataset.mn.startsWith("b."))'), true);

  // Reference.
  await b.evaluate('document.querySelector("#stats-bars [data-mn]").click()');
  await b.until('document.querySelector("[data-view=reference]").classList.contains("is-active")');
  check('reference opens on the mnemonic', (await text('.ref-main')).includes('in this program'), true);
  check('reference links to Arm', await b.evaluate('[...document.querySelectorAll(".ref-main a[href]")].some((a) => a.href.startsWith("https://developer.arm.com/documentation/ddi0602/"))'), true);

  // Strings, imports, Mach-O.
  await b.evaluate('document.querySelector("#tabs [data-view=strings]").click()');
  await b.until('[...document.querySelectorAll("#string-list .s-text")].some((n) => n.textContent.includes("Hello, world!"))');
  check('strings listed', true, true);
  await b.evaluate('document.querySelector("#tabs [data-view=imports]").click()');
  check('imports listed', (await text('#import-table')).includes('printf'), true);
  check('exports listed', [await text('#tab-imports'), (await text('#export-table')).includes('main')], ['Imports and exports', true]);
  await b.evaluate('document.querySelector("#fn-kinds [data-kind=export]").click()');
  await b.until('document.querySelectorAll("#fn-list .fn-name").length === 4');
  check('function list: exports only', await b.evaluate('[...document.querySelectorAll("#fn-list .fn-name")].map((n) => n.textContent).sort()'), ['average', 'kind', 'main', 'sum']);
  await b.evaluate('document.querySelector("#fn-kinds [data-kind=all]").click()');
  await b.evaluate('document.querySelector("#tabs [data-view=overview]").click()');
  check('Mach-O page', (await text('#overview')).includes('LC_MAIN'), true);

  // Russian, and back: the whole interface and the instruction texts follow, without reading the program again.
  const setLanguage = (value) => b.evaluate(`(() => { const s = document.getElementById("set-language"); s.value = ${JSON.stringify(value)}; s.dispatchEvent(new Event("change")); })()`);
  await setLanguage('ru');
  check('ru: tabs', await text('#tabs [data-view=listing]'), 'Код');
  check('ru: html lang', await b.evaluate('document.documentElement.lang'), 'ru');
  check('ru: overview', (await text('#overview')).includes('Сегменты и секции'), true);
  await b.evaluate('document.querySelector("#tabs [data-view=stats]").click()');
  check('ru: statistics', await text('#stats h2'), 'Статистика');
  check('ru: mnemonic summaries', /[а-яё]/i.test(await text('#stats-bars .bar-row:not(.head) .bar-sum')), true);
  await b.evaluate('document.querySelector("#stats-bars [data-mn]").click()');
  await b.until('document.querySelector("[data-view=reference]").classList.contains("is-active")');
  check('ru: reference', /[а-яё]/i.test(await text('.ref-main .insn-summary')) && (await text('.ref-main')).includes('Встречается в программе'), true);
  await b.evaluate('document.querySelector("#tabs [data-view=listing]").click()');
  // The listing was redrawn in Russian while hidden; it fills the screen again once shown.
  await b.until('document.querySelectorAll("#listing-rows .row .r-mn").length > 5');
  await b.evaluate('[...document.querySelectorAll("#listing-rows .row")].find((r) => r.querySelector(".r-mn"))?.click()');
  await b.until('/[а-яё]/i.test(document.querySelector("#inspector .insn-desc")?.textContent ?? "")');
  check('ru: inspector', (await text('#inspector')).includes('На HLA64'), true);
  if (SHOTS) await b.shot(join(SHOTS, 'ru.png'));
  await setLanguage('en');
  check('en again', await text('#tabs [data-view=listing]'), 'Code');
  check('en: inspector', (await text('#inspector')).includes('In HLA64'), true);
  await setLanguage('system');

  // A WebAssembly module: the same hello.c, built with Emscripten.
  await b.setFile('#file-input', join(root, 'tests', 'fixtures', 'hello.wasm'));
  await b.until('document.getElementById("file-name").textContent === "hello.wasm" && document.getElementById("progress").hidden');
  await b.until('document.querySelectorAll("#listing-rows .row").length > 10');
  check('wasm: arch, no platform', [await text('#file-arch'), await b.evaluate('document.getElementById("file-platform").hidden')], ['wasm32', true]);
  check('wasm: opens at main', (await text('#crumb')).startsWith('main'), true);
  check('wasm: tabs name a module', [await text('#tab-overview'), await text('#tab-imports')], ['Module', 'Imports and exports']);
  const wasmAsm = await b.evaluate('document.getElementById("listing-rows").textContent');
  check('wasm: the text format with names', /call\s*\$sum/.test(wasmAsm) && wasmAsm.includes('i32.atomic.rmw.add offset=1904'), true);
  check('wasm: source lines', wasmAsm.includes('hello.c:32'), true);
  await b.evaluate('document.getElementById("listing").focus()');
  await b.press('h');
  await b.until('document.getElementById("listing-rows").textContent.includes("fn main(l0: i32, l1: i32) -> i32 {")');
  const wasmHla = await b.evaluate('document.getElementById("listing-rows").textContent');
  check('wasm HLA64: the atomic', wasmHla.includes('atomic_add(u32[0x770], l0, seq_cst)'), true);
  check('wasm HLA64: printf with its string', wasmHla.includes('__small_printf("Hello, world! sum=%ld avg=%.2f kind=%s\\n", l2)'), true);
  if (SHOTS) await b.shot(join(SHOTS, 'wasm-hla.png'));
  await b.evaluate('[...document.querySelectorAll("#listing-rows .t-name")].find((n) => n.textContent === "sum").click()');
  await b.until('document.getElementById("crumb").textContent.startsWith("sum")');
  check('wasm: followed the call', (await text('#crumb')).startsWith('sum'), true);
  await b.evaluate('[...document.querySelectorAll("#listing-rows .row")].find((r) => r.querySelector(".r-code") && !r.classList.contains("fn"))?.click()');
  await b.until('document.querySelector("#inspector .insn-mn") !== null');
  check('wasm: the instruction explained', (await text('#inspector')).includes('In HLA64') && (await text('#inspector')).includes('WebAssembly'), true);
  await b.press('a');
  await b.evaluate('document.querySelector("#tabs [data-view=overview]").click()');
  check('wasm: the module page', (await text('#overview')).includes('WebAssembly module') && (await text('#overview')).includes('.debug_line'), true);
  await b.evaluate('document.querySelector("#tabs [data-view=imports]").click()');
  check('wasm: imports and exports', (await text('#imports')).includes('fd_write') && (await text('#imports')).includes('_start'), true);
  await b.evaluate('document.querySelector("#tabs [data-view=strings]").click()');
  await b.until('[...document.querySelectorAll("#string-list .s-text")].some((n) => n.textContent.includes("Hello, world!"))');
  check('wasm: strings', true, true);
  await b.evaluate('document.querySelector("#tabs [data-view=stats]").click()');
  await b.evaluate('document.querySelector("#stats-bars [data-mn=\'local.get\']").click()');
  await b.until('document.querySelector("[data-view=reference]").classList.contains("is-active")');
  check('wasm: the reference', (await text('.ref-main')).includes('Read a local') && (await text('.ref-main')).includes('in this program'), true);
  check('wasm: links to the specification', await b.evaluate('[...document.querySelectorAll(".ref-main a[href]")].some((a) => a.href.startsWith("https://webassembly.github.io/spec/core/"))'), true);
  await setLanguage('ru');
  check('ru: wasm tab', await text('#tab-overview'), 'Модуль');
  check('ru: wasm reference', /[а-яё]/i.test(await text('.ref-main .insn-summary')), true);
  await setLanguage('system');

  // A .NET assembly: its CIL as ildasm writes it, its HLA64 view, the Assembly and References pages.
  await b.setFile('#file-input', join(root, 'tests', 'fixtures', 'dotnet', 'hello.dll'));
  await b.until('document.getElementById("file-name").textContent === "hello.dll" && document.getElementById("progress").hidden');
  await b.until('document.querySelectorAll("#listing-rows .row").length > 10');
  check('cil: arch and platform', [await text('#file-arch'), await text('#file-platform')], ['CIL', '.NET 10.0']);
  check('cil: opens at Main', (await text('#crumb')).startsWith('Hello.Program::Main'), true);
  check('cil: an HLA64 view', await b.evaluate('!document.querySelector("[data-mode=hla]").disabled'), true);
  check('cil: tabs', [await text('#tab-overview'), await text('#tab-imports')], ['Assembly', 'References']);
  const cilAsm = await b.evaluate('document.getElementById("listing-rows").textContent');
  check('cil: ildasm text', cilAsm.includes('IL_0007') && cilAsm.includes('"--help"') && cilAsm.includes('void [System.Console]System.Console::WriteLine(string)'), true);
  await b.evaluate('[...document.querySelectorAll("#listing-rows .t-name")].find((n) => n.textContent.includes("Hello.Program::Sum")).click()');
  await b.until('document.getElementById("crumb").textContent.startsWith("Hello.Program::Sum")');
  check('cil: followed the call', (await text('#crumb')).startsWith('Hello.Program::Sum'), true);
  await b.evaluate('[...document.querySelectorAll("#listing-rows .row")].find((r) => r.querySelector(".r-code") && !r.classList.contains("fn"))?.click()');
  await b.until('document.querySelector("#inspector .insn-mn") !== null');
  check('cil: the instruction explained', (await text('#inspector')).includes('Microsoft Learn') && (await text('#inspector')).includes('In HLA64'), true);
  await b.press('h');
  await b.until('document.getElementById("listing-rows").textContent.includes("V_1 += 1")');
  const cilHla = await b.evaluate('document.getElementById("listing-rows").textContent');
  check('cil HLA64: statements', cilHla.includes('fn `Hello.Program::Sum`(values: int32[], count: int32) -> int64 {') && cilHla.includes('V_0 += i64(values[V_1])') && cilHla.includes('if V_1 < count { goto IL_0007 }'), true);
  if (SHOTS) await b.shot(join(SHOTS, 'cil-hla.png'));
  await b.press('a');
  await b.evaluate('document.querySelector("#tabs [data-view=overview]").click()');
  check('cil: the assembly page', (await text('#overview')).includes('.NETCoreApp,Version=v10.0') && (await text('#overview')).includes('#Strings'), true);
  await b.evaluate('document.querySelector("#tabs [data-view=imports]").click()');
  check('cil: references', (await text('#imports')).includes('System.Console') && (await text('#imports')).includes('libc'), true);
  await b.evaluate('document.querySelector("#tabs [data-view=strings]").click()');
  await b.until('[...document.querySelectorAll("#string-list .s-text")].some((n) => n.textContent.includes("usage: hello"))');
  check('cil: strings', true, true);
  await b.evaluate('document.querySelector("#tabs [data-view=stats]").click()');
  await b.evaluate('document.querySelector("#stats-bars [data-mn=\'ldarg.0\']").click()');
  await b.until('document.querySelector("[data-view=reference]").classList.contains("is-active")');
  check('cil: the reference', (await text('.ref-main')).includes('Load argument 0') && (await text('.ref-main')).includes('in this program'), true);
  await setLanguage('ru');
  check('ru: cil tab', await text('#tab-overview'), 'Сборка');
  check('ru: cil reference', /[а-яё]/i.test(await text('.ref-main .insn-summary')), true);
  await setLanguage('system');

  // Java bytecode: a JAR as javap writes its classes, its HLA64 view, the Classes and References pages.
  await b.setFile('#file-input', join(root, 'tests', 'fixtures', 'jvm', 'hello.jar'));
  await b.until('document.getElementById("file-name").textContent === "hello.jar" && document.getElementById("progress").hidden');
  await b.until('document.querySelectorAll("#listing-rows .row").length > 10');
  check('jvm: arch and platform', [await text('#file-arch'), await text('#file-platform')], ['JVM', 'Java 25']);
  check('jvm: opens at main', (await text('#crumb')).startsWith('hello.Hello::main'), true);
  check('jvm: an HLA64 view', await b.evaluate('!document.querySelector("[data-mode=hla]").disabled'), true);
  check('jvm: tabs', [await text('#tab-overview'), await text('#tab-imports')], ['Classes', 'References']);
  const jvmAsm = await b.evaluate('document.getElementById("listing-rows").textContent');
  check('jvm: javap text', jvmAsm.includes('getstatic') && jvmAsm.includes('#') && jvmAsm.includes('Field java/lang/System.out:Ljava/io/PrintStream;') && jvmAsm.includes('String usage: hello [numbers...]'), true);
  // The call to sum is further down main than the screen shows.
  const sumLink = '[...document.querySelectorAll("#listing-rows .t-name")].find((n) => n.textContent.startsWith("Method sum:"))';
  await b.evaluate('document.getElementById("listing").focus()');
  for (let k = 0; k < 120 && !(await b.evaluate(`!!${sumLink}`)); k++) await b.press('ArrowDown');
  await b.evaluate(`${sumLink}.click()`);
  await b.until('document.getElementById("crumb").textContent.startsWith("hello.Hello::sum")');
  check('jvm: followed the call', (await text('#crumb')).startsWith('hello.Hello::sum'), true);
  await b.evaluate('[...document.querySelectorAll("#listing-rows .row")].find((r) => r.querySelector(".r-code") && !r.classList.contains("fn"))?.click()');
  await b.until('document.querySelector("#inspector .insn-mn") !== null');
  check('jvm: the instruction explained', (await text('#inspector')).includes('JVMS') && (await text('#inspector')).includes('In HLA64'), true);
  await b.press('h');
  await b.until('document.getElementById("listing-rows").textContent.includes("total += i64(values[i])")');
  const jvmHla = await b.evaluate('document.getElementById("listing-rows").textContent');
  check('jvm HLA64: statements', jvmHla.includes('fn `hello.Hello::sum`(values: int[], count: int) -> long {') && jvmHla.includes('if i >= count { goto L25 }') && jvmHla.includes('return total'), true);
  if (SHOTS) await b.shot(join(SHOTS, 'jvm-hla.png'));
  await b.press('a');
  await b.evaluate('document.querySelector("#tabs [data-view=overview]").click()');
  check('jvm: the classes page', (await text('#overview')).includes('Main-Class') && (await text('#overview')).includes('hello.Hello$Point') && (await text('#overview')).includes('Java 25'), true);
  await b.evaluate('document.querySelector("#tabs [data-view=imports]").click()');
  check('jvm: references', (await text('#imports')).includes('java.io') && (await text('#imports')).includes('java.io.PrintStream::println'), true);
  await b.evaluate('document.querySelector("#tabs [data-view=strings]").click()');
  await b.until('[...document.querySelectorAll("#string-list .s-text")].some((n) => n.textContent.includes("usage: hello"))');
  check('jvm: strings', true, true);
  await b.evaluate('document.querySelector("#tabs [data-view=stats]").click()');
  await b.evaluate('document.querySelector("#stats-bars [data-mn=\'aload_0\']").click()');
  await b.until('document.querySelector("[data-view=reference]").classList.contains("is-active")');
  check('jvm: the reference', (await text('.ref-main')).includes('Load reference from local 0') && (await text('.ref-main')).includes('in this program'), true);
  await setLanguage('ru');
  check('ru: jvm tab', await text('#tab-overview'), 'Классы');
  check('ru: jvm reference', /[а-яё]/i.test(await text('.ref-main .insn-summary')), true);
  await setLanguage('system');

  // An Android package: the picker lists its libraries by ABI; the armeabi-v7a one is Thumb-2 and A32.
  const ANDROID = join(root, 'tests', 'fixtures', 'android');
  await b.setFile('#file-input', join(ANDROID, 'hello.apk'));
  await b.until('!document.getElementById("picker").hidden');
  check('apk: libraries by ABI', await b.evaluate('[...document.querySelectorAll("#picker-list .picker-abi")].map((n) => n.textContent)'), ['arm64-v8a', 'armeabi-v7a']);
  await b.evaluate('[...document.querySelectorAll("#picker-list .picker-item")][1].click()');
  await b.until('document.getElementById("file-name").textContent === "libhello.so" && document.getElementById("progress").hidden');
  await b.until('document.querySelectorAll("#listing-rows .row").length > 10');
  check('arm32: ABI and platform', [await text('#file-arch'), await text('#file-platform')], ['armeabi-v7a', 'Android 5.0+']);
  check('arm32: opens at JNI_OnLoad', (await text('#crumb')).startsWith('JNI_OnLoad'), true);
  check('arm32: no HLA64 view', await b.evaluate('document.querySelector("[data-mode=hla]").disabled && document.querySelector("[data-mode=asm]").getAttribute("aria-checked") === "true"'), true);
  check('arm32: tabs', [await text('#tab-overview'), await text('#tab-imports')], ['ELF', 'Imports and exports']);
  const armAsm = await b.evaluate('document.getElementById("listing-rows").textContent');
  check('arm32: literal + add pc show the string', /add\s*r1, pc\s*;\s*"hello"/.test(armAsm), true);
  check('arm32: a call to an import', armAsm.includes('__android_log_write'), true);
  check('arm32: literal pool as data', /\.word\s*0x[0-9a-f]{8}/.test(armAsm), true);
  await b.evaluate('[...document.querySelectorAll("#listing-rows .row")].find((r) => r.querySelector(".r-mn")?.textContent === "push").click()');
  await b.until('document.querySelector("#inspector .insn-mn")?.textContent === "push"');
  check('arm32: the instruction explained', (await text('#inspector')).includes('T32 (Thumb), 16 bits') && (await text('#inspector .insn-summary')).length > 3, true);
  check('arm32: links to the AArch32 pages', await b.evaluate('[...document.querySelectorAll("#inspector a[href]")].some((a) => a.href.startsWith("https://developer.arm.com/documentation/ddi0597/"))'), true);
  // Follow a call into the A32 code of arm.c (through its PLT stub).
  await b.evaluate('document.getElementById("listing").focus()');
  await b.press('k', 'KeyK', META);
  await b.until('!document.getElementById("palette").hidden');
  await b.type('Native_greet');
  await b.until('document.querySelectorAll("#palette-results .palette-item").length > 0');
  await b.press('Enter');
  await b.until('document.getElementById("crumb").textContent.startsWith("Java_com_example_hello_Native_greet")');
  await b.evaluate('[...document.querySelectorAll("#listing-rows .row.fn")].find((r) => r.textContent.startsWith("Java_com_example_hello_Native_greet")).click()');
  await b.until('(document.getElementById("inspector").textContent ?? "").includes("Uses")');
  const greet = await text('#inspector');
  check('arm32: the JNI method uses its strings and calls', ['sum=%ld avg=%.2f kind=%s scaled=%ld', 'Hello, many!', '__android_log_print', 'scale@plt'].filter((s) => !greet.includes(s)), []);
  await b.evaluate('document.querySelector("#tabs [data-view=overview]").click()');
  const elfPage = await text('#overview');
  check('arm32: ELF page facts', ['API level 21', 'liblog.so', 'worked out from the code', 'Thumb-2'].filter((s) => !elfPage.includes(s)), []);
  await b.evaluate('document.querySelector("#tabs [data-view=imports]").click()');
  check('arm32: imports with their libraries', (await text('#import-table')).includes('__android_log_print') && (await text('#import-table')).includes('@LIBC'), true);
  check('arm32: exports, a JNI method among them', /Java_com_example_hello_Native_greet.*function · T32/.test(await text('#export-table')), true);
  await b.evaluate('document.querySelector("#tabs [data-view=stats]").click()');
  await b.evaluate('document.querySelector("#stats-bars [data-mn=\'ldr\']").click()');
  await b.until('document.querySelector("[data-view=reference]").classList.contains("is-active")');
  check('arm32: the reference', (await text('.ref-main')).includes('Load register') && (await text('.ref-main')).includes('in this program'), true);
  await setLanguage('ru');
  check('ru: arm32 reference', /[а-яё]/i.test(await text('.ref-main .insn-summary')), true);
  await setLanguage('system');
  // The arm64-v8a library, opened directly: the same analysis as a Mach-O program, HLA64 included.
  await b.setFile('#file-input', join(ANDROID, 'libhello-arm64-v8a.so'));
  await b.until('document.getElementById("file-name").textContent === "libhello-arm64-v8a.so" && document.getElementById("progress").hidden');
  await b.until('document.querySelectorAll("#listing-rows .row").length > 10 && document.getElementById("file-arch").textContent === "arm64-v8a"');
  await b.until('document.getElementById("crumb").textContent.startsWith("JNI_OnLoad")', 10000).catch(() => {});
  check('arm64 ELF: ABI, platform and entry', [await text('#file-arch'), await text('#file-platform'), (await text('#crumb')).startsWith('JNI_OnLoad')], ['arm64-v8a', 'Android 5.0+', true]);
  await b.evaluate('document.getElementById("listing").focus()');
  await b.press('h');
  await b.until('document.getElementById("listing-rows").textContent.includes("fn JNI_OnLoad() {")');
  check('arm64 ELF: HLA64 names the strings', (await b.evaluate('document.getElementById("listing-rows").textContent')).includes('"loaded"'), true);
  await b.press('a');
  // A bundle of split APKs: the libraries are in the APK of each ABI.
  await b.setFile('#file-input', join(ANDROID, 'hello.apks'));
  await b.until('!document.getElementById("picker").hidden');
  check('apks: libraries from the split APKs', await b.evaluate('[...document.querySelectorAll("#picker-list .picker-item")].map((n) => n.textContent.replace(/\\s+/g, " ").trim())'), ['libhello.so split_config.arm64_v8a.apk8.8 KB', 'libhello.so split_config.armeabi_v7a.apk6.3 KB']);
  await b.press('Escape');
  check('apks: Escape closes the list', await b.evaluate('document.getElementById("picker").hidden'), true);

  // x86: a universal macOS program opens at arm64; its Mach-O page opens the x86_64 slice.
  const X86 = join(root, 'tests', 'fixtures', 'x86');
  await b.setFile('#file-input', join(X86, 'hello-macos'));
  await b.until('document.getElementById("file-name").textContent === "hello-macos" && document.getElementById("progress").hidden');
  check('universal: opens at arm64', await text('#file-arch'), 'arm64');
  await b.evaluate('document.querySelector("#tabs [data-view=overview]").click()');
  check('universal: offers the other slice', await text('#overview [data-slice]'), 'Open the x86_64 slice');
  await b.evaluate('document.querySelector("#overview [data-slice]").click()');
  await b.until('document.getElementById("file-arch").textContent === "x86_64" && document.getElementById("progress").hidden');
  await b.until('document.querySelectorAll("#listing-rows .row").length > 10');
  check('x86-64: arch, platform, title', [await text('#file-arch'), await text('#file-platform'), (await b.evaluate('document.title')).endsWith('x86-64 Disassembler')], ['x86_64', 'macOS 26.0+', true]);
  check('x86-64: opens at main', (await text('#crumb')).startsWith('main'), true);
  check('x86-64: the HLA64 view is there', await b.evaluate('!document.querySelector("[data-mode=hla]").disabled'), true);
  await b.evaluate('document.getElementById("listing").focus()');
  await b.press('h');
  await b.until('document.getElementById("listing-rows").textContent.includes("fn main() {")');
  const x86Hla = await b.evaluate('document.getElementById("listing-rows").textContent');
  check('x86-64 HLA64: a push as its stores, the atomic, a call', [x86Hla.includes('rsp -= 8; [rsp] = rbp'), x86Hla.includes('atomic_add(u64[&counter], r14, seq_cst)'), x86Hla.includes('sum()')], [true, true, true]);
  await b.press('a');
  await b.evaluate('document.querySelector("#tabs [data-view=listing]").click()');
  await b.until('/call\\s*sum/.test(document.getElementById("listing-rows").textContent)');
  const x86Asm = await b.evaluate('document.getElementById("listing-rows").textContent');
  check('x86-64: calls named, the atomic', [/call\s*sum/.test(x86Asm), /call\s*step/.test(x86Asm), x86Asm.includes('lock')], [true, true, true]);
  await b.evaluate('[...document.querySelectorAll("#listing-rows .row.fn")].find((r) => r.textContent.startsWith("main")).click()');
  await b.until('(document.getElementById("inspector").textContent ?? "").includes("Uses")');
  const x86Main = await text('#inspector');
  check('x86-64: main uses the greeting and calls printf', ['Hello, x86!', 'printf', 'strcmp', 'scale4'].filter((s) => !x86Main.includes(s)), []);
  await b.evaluate('[...document.querySelectorAll("#fn-list .fn-name")].find((n) => n.textContent === "step").click()');
  await b.until('document.getElementById("crumb").textContent.startsWith("step")');
  check('x86-64: the switch', (await b.evaluate('document.getElementById("listing-rows").textContent')).includes('switch: 8 cases'), true);
  await b.evaluate('[...document.querySelectorAll("#listing-rows .row")].find((r) => r.querySelector(".r-mn")?.textContent === "push").click()');
  await b.until('document.querySelector("#inspector .insn-mn")?.textContent === "push"');
  check('x86-64: the instruction explained', [(await text('#inspector .insn-summary')).length > 3, (await text('#inspector')).includes('55')], [true, true]);
  check('x86-64: links to the x86 reference', await b.evaluate('[...document.querySelectorAll("#inspector a[href]")].some((a) => a.href === "https://www.felixcloutier.com/x86/push")'), true);
  await b.evaluate('document.querySelector("#tabs [data-view=imports]").click()');
  check('x86-64: imports and their calls', /printf.*1/.test(await text('#import-table')), true);
  // An Android library for x86 (i386): its strings are reached through the GOT register.
  await b.setFile('#file-input', join(X86, 'libhello-x86.so'));
  await b.until('document.getElementById("file-name").textContent === "libhello-x86.so" && document.getElementById("progress").hidden');
  await b.until('document.querySelectorAll("#listing-rows .row").length > 10');
  check('x86: ABI and platform', [await text('#file-arch'), await text('#file-platform')], ['x86', 'Android 5.0+']);
  check('x86: no HLA64 view (HLA64 has no 32-bit x86 target)', await b.evaluate('document.querySelector("[data-mode=hla]").disabled'), true);
  await b.evaluate('[...document.querySelectorAll("#fn-list .fn-name")].find((n) => n.textContent === "main").click()');
  await b.until('document.getElementById("crumb").textContent.startsWith("main")');
  check('x86: the GOT register made from call / pop / add', /pop\s*ebx.*add\s*ebx, 0x[0-9a-f]+/s.test(await b.evaluate('document.getElementById("listing-rows").textContent')), true);
  await b.evaluate('[...document.querySelectorAll("#listing-rows .row.fn")].find((r) => r.textContent.startsWith("main")).click()');
  await b.until('(document.getElementById("inspector").textContent ?? "").includes("Uses")');
  check('x86: strings reached through ebx', (await text('#inspector')).includes('Hello, x86!'), true);
  await setLanguage('ru');
  check('ru: x86 title', (await b.evaluate('document.title')).endsWith('Дизассемблер x86'), true);
  await setLanguage('system');
  // A Windows DLL: the PE page, its exports, the import thunks.
  await b.setFile('#file-input', join(X86, 'hello-x64.dll'));
  await b.until('document.getElementById("file-name").textContent === "hello-x64.dll" && document.getElementById("progress").hidden');
  await b.until('document.getElementById("file-platform").textContent === "Windows Vista+"');
  check('PE: tabs', [await text('#tab-overview'), await text('#tab-imports')], ['PE', 'Imports and exports']);
  await b.evaluate('document.querySelector("#tabs [data-view=overview]").click()');
  const pePage = await text('#overview');
  check('PE: the page', ['x86-64 (PE32+)', 'dynamic library (DLL)', 'KERNEL32.dll', '.text', 'Exception'].filter((s) => !pePage.includes(s)), []);
  await b.evaluate('document.querySelector("#tabs [data-view=imports]").click()');
  check('PE: exports', /step.*function/.test(await text('#export-table')), true);

  // Windows on Arm: an ARM64X library opens at its Arm code; its PE page opens the x64 code.
  const WINARM = join(root, 'tests', 'fixtures', 'winarm');
  await b.setFile('#file-input', join(WINARM, 'arm64x.dll'));
  await b.until('document.getElementById("file-name").textContent === "arm64x.dll" && document.getElementById("progress").hidden');
  await b.until('document.getElementById("file-arch").textContent === "arm64x"');
  await b.evaluate('document.querySelector("#tabs [data-view=overview]").click()');
  const hybridPage = await text('#overview');
  check('ARM64X: the code map', ['ARM64X', 'Code map', 'ARM64EC', 'Open the x64 code'].filter((s) => !hybridPage.includes(s)), []);
  await b.evaluate('document.querySelector("#overview [data-slice=x64]").click()');
  await b.until('document.getElementById("file-arch").textContent === "x86_64" && document.getElementById("progress").hidden');
  await b.until('[...document.querySelectorAll("#fn-list *")].some((e) => e.textContent === "xmul")');
  check('ARM64X: the x64 code, named', true, true);
  // 32-bit Arm Windows: Thumb-2 through the AArch32 analysis.
  await b.setFile('#file-input', join(WINARM, 'hello-arm.exe'));
  await b.until('document.getElementById("file-name").textContent === "hello-arm.exe" && document.getElementById("progress").hidden');
  await b.until('document.querySelectorAll("#listing-rows .row").length > 10');
  check('Windows arm: opens at main, Thumb', [await text('#crumb'), await b.evaluate('document.querySelector("[data-mode=hla]").disabled'), await text('#file-arch')], ['main', true, 'armv7']);

  // An iOS app: the picker lists the app and its framework; Objective-C names the methods.
  await b.setFile('#file-input', join(root, 'tests', 'fixtures', 'ios', 'Hello.ipa'));
  await b.until('!document.getElementById("picker").hidden');
  check('ipa: the picker', [await text('#picker-title'), await b.evaluate('[...document.querySelectorAll("#picker-list .picker-abi")].map((n) => n.textContent)')], ['Open a program from the app', ['App', 'Frameworks']]);
  await b.evaluate('document.querySelector("#picker-list .picker-item").click()');
  await b.until('document.getElementById("file-name").textContent === "Hello" && document.getElementById("progress").hidden');
  await b.until('document.getElementById("file-platform").textContent === "iOS 15.0+" && document.querySelectorAll("#listing-rows .row").length > 10');
  // The function list fills a moment after the listing.
  const methodsShown = '["-[Greeter initWithName:]", "+[Greeter defaultGreeter]", "objc_msgSend$copy"].every((n) => [...document.querySelectorAll("#fn-list *")].some((e) => e.textContent === n))';
  await b.until(methodsShown).catch(() => {});
  check('ipa: methods name the functions', await b.evaluate(methodsShown), true);
  await b.evaluate('document.getElementById("listing").focus()');
  await b.press('h');
  await b.until('document.getElementById("listing-rows").textContent.includes("fn main() {")');
  await b.press('k', 'KeyK', META);
  await b.until('!document.getElementById("palette").hidden');
  await b.type('Greeter greeting');
  await b.until('document.querySelectorAll("#palette-results .palette-item").length > 0');
  await b.press('Enter');
  await b.until('document.getElementById("listing-rows").textContent.includes("@\\"Hello, %@!\\"")');
  check('ipa: HLA64 writes NSString constants', true, true);
  await b.press('a');
  await b.evaluate('document.querySelector("#tabs [data-view=overview]").click()');
  const iosPage = await text('#overview');
  check('ipa: bundle and Objective-C on the page', ['Payload/Hello.app · com.example.hello', '1.2 (34)', 'iPhoneOS 15.0+', '1 class', 'NSString (Shouting)', 'NSObject'].filter((s) => !iosPage.includes(s)), []);

  // Patching: change an instruction, see it marked, download the signed file, undo.
  await b.setFile('#file-input', PROGRAM);
  await b.until('document.getElementById("file-name").textContent === "hello" && document.getElementById("progress").hidden');
  // The rows of this program (its addresses are above 4 GB), not the ones of the program before.
  await b.until('document.getElementById("file-arch").textContent === "arm64" && [...document.querySelectorAll("#listing-rows .r-addr")].some((a) => a.textContent.startsWith("1000"))');
  await b.until('document.querySelectorAll("#listing-rows .row .r-mn").length > 5');
  await b.evaluate('[...document.querySelectorAll("#listing-rows .row")].find((r) => r.querySelector(".r-mn")).click()');
  check('an instruction offers a change', await b.evaluate('!!document.querySelector("#inspector [data-edit]")'), true);
  await b.evaluate('document.querySelector("#inspector [data-edit]").click()');
  check('the editor opens with the instruction', [await b.evaluate('!document.getElementById("editor").hidden'), (await text('#editor-before')).length > 3], [true, true]);
  check('quick changes are offered', await b.evaluate('[...document.querySelectorAll("#editor-quick .chip")].map((c) => c.textContent).includes("nop")'), true);
  // Type the bytes of nop; the preview decodes them.
  await b.evaluate('const i = document.getElementById("editor-input"); i.value = "d503201f"; i.dispatchEvent(new Event("input"))');
  check('the preview decodes what will be written', (await text('#editor-preview')).includes('nop'), true);
  check('apply is enabled', await b.evaluate('!document.getElementById("editor-apply").disabled'), true);
  await b.evaluate('document.getElementById("editor-apply").click()');
  await b.until('document.querySelectorAll("#listing-rows .row.is-patched").length > 0');
  check('the row is marked and shows the new instruction', [await b.evaluate('document.querySelectorAll("#listing-rows .row.is-patched").length'), (await b.evaluate('document.querySelector("#listing-rows .row.is-patched .r-mn").textContent'))], [1, 'nop']);
  check('the change bar shows the count', await b.evaluate('!document.getElementById("patch-bar").hidden && /1/.test(document.getElementById("patch-count").textContent)'), true);
  // Re-open: a patched instruction can be reverted.
  await b.evaluate('document.querySelector("#listing-rows .row.is-patched").click()');
  await b.evaluate('document.querySelector("#inspector [data-edit]").click()');
  check('a patched instruction offers Revert', await b.evaluate('[...document.querySelectorAll("#editor-quick .chip")].some((c) => c.textContent === document.querySelector("#editor-quick .chip").textContent && /Revert|Вернуть/.test(c.textContent))'), true);
  await b.press('Escape');
  check('Escape closes the editor', await b.evaluate('document.getElementById("editor").hidden'), true);
  if (process.platform === 'darwin' && spawnSync('codesign', ['--help']).error === undefined) {
    const downloads = mkdtempSync(join(tmpdir(), 'app-dl-'));
    await b.downloadsTo(downloads);
    await b.evaluate('document.getElementById("patch-download").click()');
    await b.until(`${JSON.stringify(downloads)} && true`); // give the click a tick
    let file;
    for (let i = 0; i < 40 && !file; i++) {
      file = readdirSync(downloads).find((f) => !f.endsWith('.crdownload'));
      if (!file) await new Promise((r) => setTimeout(r, 100));
    }
    check('the file downloads with -patched in its name', /-patched$/.test(file ?? ''), true);
    const out = join(downloads, file);
    chmodSync(out, 0o755);
    check('codesign accepts the re-signed download', spawnSync('codesign', ['--verify', '--strict', out]).status, 0);
    rmSync(downloads, { recursive: true, force: true });
  }
  await b.evaluate('document.getElementById("patch-reset").click()');
  await b.until('document.querySelectorAll("#listing-rows .row.is-patched").length === 0');
  check('Undo all clears the changes', [await b.evaluate('document.querySelectorAll("#listing-rows .row.is-patched").length'), await b.evaluate('document.getElementById("patch-bar").hidden')], [0, true]);

  // Theme.
  await b.evaluate('document.getElementById("theme").click()');
  check('theme switches', await b.evaluate('document.documentElement.dataset.theme'), 'light');

  check('no errors on the page', b.errors, []);
} finally {
  await b.close();
}
done('app');
