/**
 * The page: opening a program, the tabs, the listing modes, the function
 * list, the settings and the keys. The work itself is in src/core (no DOM)
 * and the other modules of src/app.
 */

import type { Disassembly } from '../core/disassembly';
import { analyzeArm32 } from '../core/arm32/program';
import { EM, isElf, NotElf, parseElf } from '../core/elf';
import { fromElf, fromMachO, fromPe } from '../core/image';
import { loadEngine } from '../core/engine/engine';
import { NotMachO, parseMachO } from '../core/macho';
import { isPe, MACHINE, NotPe, parsePe } from '../core/pe';
import { Archive, isZip, NotZip, type Bundle, type BundledProgram, type PackagedLibrary } from '../core/archive';
import { analyze, type Fn } from '../core/program';
import { isWasm as isWasmFile, NotWasm, parseWasm } from '../core/wasm/module';
import { analyzeWasm } from '../core/wasm/program';
import { analyzeX86 } from '../core/x86/program';
import { analyzeCil, NotCil } from '../core/cil/program';
import { isClassFile, NotClass } from '../core/jvm/program';
import { analyzeJvm, holdsClasses, isJmod } from '../core/jvm/program';
import { detectLanguage, isLanguage, n, setLanguage, t, tn, translatePage } from '../core/i18n';
import { initInspector } from './inspector';
import { Listing } from './listing';
import { initPages, renderImports, renderOverview, renderStats, renderStrings } from './pages';
import { closePalette, initPalette, openPalette } from './palette';
import { fill as fillReference, initReference, relocalizeReference, show as showReference } from './reference';
import { assemble } from '../core/arm64/encode';
import { initPatch, openEditor, resetPatches, setAssembler } from './patch';
import { startServiceWorker } from './pwa';
import { emit, fnName, modeFor, noHla, on, PANEL_WIDTHS, rowsFor, saveSettings, select, settings, state, type LanguageSetting, type Theme } from './state';
import { sizeLabel } from './labels';
import { $, esc, installTooltips, isMac, toast, VirtualList } from './ui';
import { viewOf } from './views';

/** The language the settings ask for: the browser's first one we have, or the one picked. */
function applyLanguage(): void {
  setLanguage(isLanguage(settings.language) ? settings.language : detectLanguage());
  translatePage();
  if (!state.program) document.title = t('bar', 'Disassembler for Arm and WebAssembly');
}

/** The page's title with a program open. */
function title(): string {
  return `${state.fileName} — ${viewOf(state.program!).title()}`;
}

/** The tabs that name what the file is: Mach-O, ELF or Module, Imports or — when it exports anything — Imports and exports. */
function labelTabs(): void {
  const view = state.program && viewOf(state.program);
  $('tab-overview').textContent = view ? view.overviewTab() : t('tabs', 'Mach-O');
  $('tab-imports').textContent = view ? view.importsTab() : t('tabs', 'Imports');
}
applyLanguage();

const listing = new Listing();
let fnList: VirtualList<Fn> | null = null;
let fnKind = 'all';
let currentView = 'listing';

/* ------------------------------------------------------------------ *
 * Theme and settings
 * ------------------------------------------------------------------ */

function applyTheme(): void {
  document.documentElement.dataset.theme = settings.theme;
}

function applySettings(): void {
  applyTheme();
  $('workspace').style.setProperty('--sidebar-w', `${settings.sidebarWidth}px`);
  $('workspace').style.setProperty('--inspector-w', `${settings.inspectorWidth}px`);
  $<HTMLInputElement>('show-bytes').checked = settings.bytes;
  $<HTMLInputElement>('show-arrows').checked = settings.arrows;
  $<HTMLSelectElement>('set-language').value = settings.language;
  $<HTMLSelectElement>('set-theme').value = settings.theme;
  $<HTMLSelectElement>('set-names').value = settings.names;
  $<HTMLInputElement>('set-inspector').checked = settings.inspector;
  $('workspace').classList.toggle('no-inspector', !settings.inspector || ['reference', 'stats', 'overview'].includes(currentView));
  for (const button of document.querySelectorAll<HTMLButtonElement>('#mode [data-mode]')) {
    button.setAttribute('aria-checked', String(button.dataset.mode === modeFor(settings.mode)));
    // HLA64 has no 32-bit Arm target: that code is shown as assembly only.
    const unavailable = button.dataset.mode === 'hla' && noHla(state.program);
    button.disabled = unavailable;
    if (unavailable) button.dataset.tip = esc(noHlaReason());
    else delete button.dataset.tip;
  }
}

on('settings', applySettings);
applySettings();

/* ------------------------------------------------------------------ *
 * Resizing the side panels
 * ------------------------------------------------------------------ */

/**
 * The borders of the function list and the details panel move: by dragging,
 * by the arrow keys when focused (Shift for bigger steps), and back to the
 * usual width on a double-click. The listing in the middle keeps at least
 * 360 pixels; the width is remembered with the other settings.
 */
function initResizer(id: string, key: 'sidebarWidth' | 'inspectorWidth', side: 'left' | 'right'): void {
  const handle = $(id);
  const variable = key === 'sidebarWidth' ? '--sidebar-w' : '--inspector-w';
  const other = key === 'sidebarWidth' ? 'inspectorWidth' : 'sidebarWidth';
  const clamp = (value: number) => {
    const workspace = $('workspace').getBoundingClientRect();
    const otherShown = other === 'inspectorWidth' ? !$('workspace').classList.contains('no-inspector') : !$('workspace').classList.contains('no-sidebar');
    const max = workspace.width - (otherShown ? settings[other] : 0) - 360;
    return Math.round(Math.max(180, Math.min(value, max)));
  };
  let width = 0;
  const show = (value: number) => {
    width = clamp(value);
    $('workspace').style.setProperty(variable, `${width}px`);
    handle.setAttribute('aria-valuenow', String(width));
  };
  handle.addEventListener('pointerdown', (event) => {
    if (event.button !== 0) return;
    event.preventDefault();
    handle.setPointerCapture(event.pointerId);
    handle.classList.add('is-dragging');
    document.body.classList.add('is-resizing');
    const workspace = $('workspace').getBoundingClientRect();
    const move = (e: PointerEvent) => show(side === 'left' ? e.clientX - workspace.left : workspace.right - e.clientX);
    const up = () => {
      handle.removeEventListener('pointermove', move);
      handle.removeEventListener('pointerup', up);
      handle.removeEventListener('pointercancel', up);
      handle.classList.remove('is-dragging');
      document.body.classList.remove('is-resizing');
      if (width) saveSettings({ [key]: width });
    };
    handle.addEventListener('pointermove', move);
    handle.addEventListener('pointerup', up);
    handle.addEventListener('pointercancel', up);
  });
  handle.addEventListener('dblclick', () => {
    show(PANEL_WIDTHS[key]);
    saveSettings({ [key]: width });
  });
  handle.addEventListener('keydown', (event) => {
    const step = event.shiftKey ? 64 : 16;
    const grow = side === 'left' ? 1 : -1;
    let delta = 0;
    if (event.key === 'ArrowRight') delta = step * grow;
    else if (event.key === 'ArrowLeft') delta = -step * grow;
    else return;
    event.preventDefault();
    show(settings[key] + delta);
    saveSettings({ [key]: width });
  });
}

initResizer('resize-sidebar', 'sidebarWidth', 'left');
initResizer('resize-inspector', 'inspectorWidth', 'right');

$('theme').addEventListener('click', () => {
  const order: Theme[] = ['system', 'light', 'dark'];
  const next = order[(order.indexOf(settings.theme) + 1) % order.length]!;
  saveSettings({ theme: next });
  toast({ system: t('bar', 'Theme: as the system'), light: t('bar', 'Theme: light'), dark: t('bar', 'Theme: dark') }[next]);
});
$('show-bytes').addEventListener('change', (event) => saveSettings({ bytes: (event.target as HTMLInputElement).checked }));
$('show-arrows').addEventListener('change', (event) => saveSettings({ arrows: (event.target as HTMLInputElement).checked }));
$('set-language').addEventListener('change', (event) => {
  saveSettings({ language: (event.target as HTMLSelectElement).value as LanguageSetting });
  applyLanguage();
  relocalize();
});
$('set-theme').addEventListener('change', (event) => saveSettings({ theme: (event.target as HTMLSelectElement).value as Theme }));
$('set-names').addEventListener('change', (event) => {
  saveSettings({ names: (event.target as HTMLSelectElement).value as 'short' | 'full' | 'raw' });
  state.context = null;
  fillFunctions();
});
$('set-inspector').addEventListener('change', (event) => saveSettings({ inspector: (event.target as HTMLInputElement).checked }));
$('menu-open').addEventListener('click', () => {
  $('menu').hidden = false;
});
$('menu-close').addEventListener('click', () => {
  $('menu').hidden = true;
});
$('menu').addEventListener('mousedown', (event) => {
  if (event.target === $('menu')) $('menu').hidden = true;
});
$('open-another').addEventListener('click', () => {
  $('menu').hidden = true;
  $<HTMLInputElement>('file-input').click();
});

$('version').textContent = __APP_VERSION__;
$('search-key').textContent = isMac ? '⌘K' : 'Ctrl K';

/* ------------------------------------------------------------------ *
 * Opening a program
 * ------------------------------------------------------------------ */

function progress(stage: string, done: number, total: number): void {
  $('progress').hidden = false;
  $('progress-stage').textContent = stage;
  $('progress-bar').style.width = `${total ? Math.round((done / total) * 100) : 0}%`;
  $('progress-detail').textContent = total > 1 ? `${n(done)} / ${n(total)}` : '';
}

async function openFile(file: File): Promise<void> {
  $('start-error').textContent = '';
  progress(t('open', 'Reading {name}', { name: file.name }), 0, 1);
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(await file.arrayBuffer());
  } catch (err) {
    failed(err);
    $('progress').hidden = true;
    return;
  }
  if (isZip(bytes)) {
    // The core reads the archive: it is loaded first.
    await loadEngine();
    const archive = new Archive(bytes);
    // A JAR (or a WAR, an AAR) is a ZIP of classes: it opens as one program.
    if (holdsClasses(namesOrNone(archive))) {
      await openBytes(bytes, file.name);
      return;
    }
    let programs: BundledProgram[] = [];
    try {
      programs = archive.programs();
    } catch (err) {
      failed(err);
      $('progress').hidden = true;
      return;
    }
    if (programs.length) chooseBundled(file.name, programs);
    else await choosePackaged(file.name, archive);
    $('progress').hidden = true;
    return;
  }
  await openBytes(bytes, file.name);
}

/** The names in a ZIP's directory, or none when it cannot be read. */
function namesOrNone(archive: Archive): string[] {
  try {
    return archive.names();
  } catch {
    return [];
  }
}

/** Shows what could not be opened, where the person is looking. */
function failed(err: unknown): void {
  const known = err instanceof NotMachO || err instanceof NotWasm || err instanceof NotCil || err instanceof NotClass || err instanceof NotElf || err instanceof NotZip || err instanceof NotPe;
  const message = known ? err.message : t('open', 'The file could not be read: {reason}', { reason: err instanceof Error ? err.message : String(err) });
  $('start-error').textContent = message;
  if (!$('workspace').hidden) toast(message);
  if (!known) console.error(err);
}

/** What the HLA64 switch says when the open program has no HLA64 view. */
function noHlaReason(): string {
  return (state.program && viewOf(state.program).noHla()) ?? '';
}

/** Opens another slice of the universal file that is open: `x86_64`, `arm64`. */
async function openSlice(slice: string): Promise<void> {
  if (!state.fileBytes) return;
  await openBytes(state.fileBytes, state.fileName, slice);
}

/** Opens a program; `bundle` is the app bundle it was taken from (another slice of the same file keeps it). */
async function openBytes(bytes: Uint8Array, name: string, slice?: string, bundle = slice ? state.bundle : undefined): Promise<void> {
  try {
    const stages = { decode: t('open', 'Decoding instructions'), functions: t('open', 'Finding functions'), done: t('open', 'Done') };
    const report = (stage: keyof typeof stages, done: number, total: number) => progress(stages[stage], done, total);
    let program: Disassembly;
    // What the open program holds in the core goes first, so the next one can use the room; it is read again should it stay open.
    state.program?.dispose();
    // The core reads the containers too: it must be there first.
    await loadEngine();
    if (isWasmFile(bytes)) {
      program = await analyzeWasm(parseWasm(bytes), report);
    } else if (isClassFile(bytes) || isJmod(bytes) || isZip(bytes)) {
      // Java bytecode: a class file (whose magic number a universal Mach-O file shares), a JAR, a .jmod.
      program = await analyzeJvm(bytes, report);
    } else if (isPe(bytes)) {
      const pe = parsePe(bytes);
      // A .NET assembly: its code is CIL, whatever the machine its header names (mixed-mode C++/CLI has native code too, not shown).
      if (pe.clr) program = await analyzeCil(pe, report);
      // ARM64EC and ARM64X: Arm code and x64 code in one file, opened one kind at a time (`slice`: 'x64').
      else if (pe.hybrid) program = slice === 'x64' ? await analyzeX86(fromPe(pe, 'x64'), report) : await analyze(fromPe(pe, 'arm'), report);
      else if (pe.machine === MACHINE.AMD64 || pe.machine === MACHINE.I386) program = await analyzeX86(fromPe(pe), report);
      else if (pe.machine === MACHINE.ARM64) program = await analyze(fromPe(pe), report);
      else if (pe.machine === MACHINE.ARMNT) program = await analyzeArm32(fromPe(pe), report);
      else throw new NotPe(t('open', 'This Windows program is built for {arch}. The disassembler reads x86-64, i386, arm64 and 32-bit Arm code.', { arch: pe.machineName }));
    } else if (isElf(bytes)) {
      const elf = parseElf(bytes);
      if (elf.machine === EM.ARM) program = await analyzeArm32(fromElf(elf), report);
      else if (elf.machine === EM.AARCH64) program = await analyze(fromElf(elf), report);
      else if (elf.machine === EM.X86_64 || elf.machine === EM.X86) program = await analyzeX86(fromElf(elf), report);
      else throw new NotElf(t('open', 'This library is built for {arch}. The disassembler reads arm64, 32-bit Arm and x86 code.', { arch: elf.arch }));
    } else {
      let image = parseMachO(bytes, slice);
      // A universal file without an arm64 slice opens at its x86_64 one.
      if (!slice && !/^arm64e?$/.test(image.arch) && image.arches.some((a) => a.name === 'x86_64')) image = parseMachO(bytes, 'x86_64');
      // Old iOS apps carry armv7 next to arm64, and old macOS ones i386 next to x86_64: the 64-bit slice opens first.
      // An app from the App Store keeps its code encrypted until the device that runs it decrypts it.
      if (image.encrypted) throw new NotMachO(t('open', 'This program is encrypted by the App Store (FairPlay): its code can be read only from a copy decrypted on a device, where the encryption load command says cryptid 0.'));
      if (/^arm64e?$/.test(image.arch)) program = await analyze(fromMachO(image), report);
      else if (image.arch === 'x86_64' || image.arch === 'i386') program = await analyzeX86(fromMachO(image), report);
      else if (image.cputype === 12 && /^armv7|^arm$/.test(image.arch)) program = await analyzeArm32(fromMachO(image), report);
      else throw new NotMachO(t('open', 'This program is built for {arch}. The disassembler reads arm64, x86-64, i386 and 32-bit Arm code.', { arch: image.arch }));
    }
    state.program = program;
    state.fileName = name;
    state.fileSize = bytes.length;
    state.fileBytes = bytes;
    state.bundle = bundle;
    resetPatches();
    state.rows.clear();
    state.context = null;
    state.history = [];
    state.future = [];
    state.selection = null;
    showWorkspace();
  } catch (err) {
    failed(err);
  } finally {
    $('progress').hidden = true;
  }
}

/* ------------------------------------------------------------------ *
 * Android packages
 * ------------------------------------------------------------------ */

/** The ABIs whose code the disassembler reads, in the order the picker lists them. */
const ABIS = ['arm64-v8a', 'armeabi-v7a', 'armeabi', 'x86_64', 'x86'];

/**
 * An APK (or .aab, or a bundle of split APKs: .apks, .xapk) is a ZIP file:
 * its native libraries are listed by ABI, and the one picked is taken out and
 * opened. A package with a single library opens it at once.
 */
async function choosePackaged(name: string, archive: Archive): Promise<void> {
  let libraries: PackagedLibrary[];
  try {
    libraries = archive.libraries();
  } catch (err) {
    failed(err);
    return;
  }
  if (!libraries.length) {
    failed(new NotZip(t('open', 'The package holds no native libraries (lib/<abi>/*.so); its code is Java or Kotlin bytecode, which this disassembler does not read.')));
    return;
  }
  const open = async (lib: PackagedLibrary) => {
    $('picker').hidden = true;
    progress(t('open', 'Reading {name}', { name: lib.file }), 0, 1);
    try {
      await openBytes(await lib.read(), lib.file);
    } catch (err) {
      failed(err);
      $('progress').hidden = true;
    }
  };
  const readable = libraries.filter((l) => ABIS.includes(l.abi));
  if (libraries.length === 1 && readable.length === 1) {
    void open(readable[0]!);
    return;
  }
  const abis = [...new Set(libraries.map((l) => l.abi))].sort((a, b) => (ABIS.indexOf(a) + 1 || 99) - (ABIS.indexOf(b) + 1 || 99) || a.localeCompare(b));
  $('picker-title').textContent = t('picker', 'Open a library from the package');
  $('picker-file').textContent = `${name} · ${tn('open', '{count} native library', '{count} native libraries', libraries.length)}`;
  $('picker-list').innerHTML = abis
    .map((abi) => {
      const ok = ABIS.includes(abi);
      const items = libraries
        .filter((l) => l.abi === abi)
        .sort((a, b) => b.size - a.size)
        .map((l) => `<button class="picker-item" type="button" data-entry="${libraries.indexOf(l)}"${ok ? '' : ' disabled'}><span>${esc(l.file)}${l.from ? ` <span class="hint">${esc(l.from)}</span>` : ''}</span><span class="picker-size">${esc(sizeLabel(l.size))}</span></button>`)
        .join('');
      return `<div class="picker-abi">${esc(abi)}${ok ? '' : ` <span class="hint">— ${esc(t('open', 'not code this disassembler reads'))}</span>`}</div>${items}`;
    })
    .join('');
  $('picker-list').onclick = (event) => {
    const item = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-entry]');
    if (item && !item.disabled) void open(libraries[Number(item.dataset.entry)]!);
  };
  $('picker').hidden = false;
  document.querySelector<HTMLButtonElement>('#picker-list .picker-item:not(:disabled)')?.focus();
}

/** The kinds of programs in an app, in the order the picker lists them. */
const BUNDLE_KINDS: Bundle['kind'][] = ['app', 'extension', 'framework', 'bundle', 'library'];

/**
 * An app archive (.ipa, or a zipped .app) holds the app's executable and those of its frameworks
 * and extensions; the one picked is taken out and opened. An app with nothing else opens at once.
 */
function chooseBundled(name: string, programs: BundledProgram[]): void {
  const open = async (item: BundledProgram) => {
    $('picker').hidden = true;
    progress(t('open', 'Reading {name}', { name: item.file }), 0, 1);
    try {
      await openBytes(await item.read(), item.file, undefined, item.bundle);
    } catch (err) {
      failed(err);
      $('progress').hidden = true;
    }
  };
  if (programs.length === 1) {
    void open(programs[0]!);
    return;
  }
  const kindLabel = (kind: Bundle['kind']) =>
    ({ app: t('picker', 'App'), extension: t('picker', 'Extensions'), framework: t('picker', 'Frameworks'), bundle: t('picker', 'Bundles'), library: t('picker', 'Libraries') })[kind];
  const sorted = [...programs].sort((a, b) => BUNDLE_KINDS.indexOf(a.bundle.kind) - BUNDLE_KINDS.indexOf(b.bundle.kind) || a.bundle.path.localeCompare(b.bundle.path));
  $('picker-title').textContent = t('picker', 'Open a program from the app');
  $('picker-file').textContent = `${name} · ${tn('picker', '{count} program', '{count} programs', programs.length)}`;
  $('picker-list').innerHTML = BUNDLE_KINDS.filter((kind) => sorted.some((p) => p.bundle.kind === kind))
    .map((kind) => {
      const items = sorted
        .filter((p) => p.bundle.kind === kind)
        .map((p) => {
          const hint = p.bundle.identifier ?? p.bundle.path;
          return `<button class="picker-item" type="button" data-entry="${programs.indexOf(p)}"><span>${esc(p.file)}${hint ? ` <span class="hint">${esc(hint)}</span>` : ''}</span><span class="picker-size">${esc(sizeLabel(p.size))}</span></button>`;
        })
        .join('');
      return `<div class="picker-abi">${esc(kindLabel(kind))}</div>${items}`;
    })
    .join('');
  $('picker-list').onclick = (event) => {
    const item = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-entry]');
    if (item) void open(programs[Number(item.dataset.entry)]!);
  };
  $('picker').hidden = false;
  document.querySelector<HTMLButtonElement>('#picker-list .picker-item')?.focus();
}

$('picker-close').addEventListener('click', () => {
  $('picker').hidden = true;
});
$('picker').addEventListener('mousedown', (event) => {
  if (event.target === $('picker')) $('picker').hidden = true;
});

/** Draws everything again in the new language; the program itself is not read again. */
function relocalize(): void {
  emit('language');
  if (!state.program) return;
  document.title = title();
  labelTabs();
  renderStats();
  renderStrings();
  renderImports();
  renderOverview();
  relocalizeReference();
  fillFunctions();
  listing.draw();
  emit('settings');
}

function showWorkspace(): void {
  const p = state.program!;
  document.title = title();
  labelTabs();
  $('start').hidden = true;
  $('workspace').hidden = false;
  for (const id of ['tabs', 'mode', 'search-open', 'file-chip']) $(id).hidden = false;
  $('file-name').textContent = state.fileName;
  $('file-arch').textContent = p.archLabel();
  const platform = p.platformLabel();
  $('file-platform').hidden = !platform;
  $('file-platform').textContent = platform ?? '';
  applySettings();
  renderStats();
  renderStrings();
  renderImports();
  renderOverview();
  fillReference();
  fillFunctions();
  listing.show(rowsFor(settings.mode));
  emit('open');
  showView('listing');
  const entry = viewOf(p).entry();
  if (entry !== undefined) listing.goTo(entry, false);
  listing.focus();
  toast(tn('open', '{count} instruction decoded', '{count} instructions decoded', p.totalInstructions));
}

const input = $<HTMLInputElement>('file-input');
input.addEventListener('change', () => {
  const file = input.files?.[0];
  if (file) void openFile(file);
  input.value = '';
});
const drop = $('drop');
drop.addEventListener('click', () => input.click());
drop.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    input.click();
  }
});
window.addEventListener('dragover', (event) => {
  event.preventDefault();
  drop.classList.add('is-over');
});
window.addEventListener('dragleave', (event) => {
  if (!event.relatedTarget) drop.classList.remove('is-over');
});
window.addEventListener('drop', (event) => {
  event.preventDefault();
  drop.classList.remove('is-over');
  const file = event.dataTransfer?.files[0];
  if (file) void openFile(file);
});

/* ------------------------------------------------------------------ *
 * Views, modes, functions
 * ------------------------------------------------------------------ */

function showView(view: string): void {
  currentView = view;
  for (const tab of document.querySelectorAll<HTMLElement>('#tabs .tab')) tab.classList.toggle('is-active', tab.dataset.view === view);
  for (const pane of document.querySelectorAll<HTMLElement>('.views .view')) pane.classList.toggle('is-active', pane.dataset.view === view);
  $('mode').style.visibility = view === 'listing' ? 'visible' : 'hidden';
  $('workspace').classList.toggle('no-sidebar', view === 'reference');
  // The details panel belongs to what can be selected: code, strings, imports.
  $('workspace').classList.toggle('no-inspector', !settings.inspector || view === 'reference' || view === 'stats' || view === 'overview');
  if (view === 'listing') {
    listing.draw();
    listing.focus();
  }
  emit('view');
}

$('tabs').addEventListener('click', (event) => {
  const tab = (event.target as HTMLElement).closest<HTMLElement>('[data-view]');
  if (tab) showView(tab.dataset.view!);
});

function setMode(mode: 'asm' | 'hla'): void {
  if (!state.program || settings.mode === mode) return;
  if (mode === 'hla' && noHla(state.program)) {
    toast(noHlaReason());
    return;
  }
  saveSettings({ mode });
  listing.show(rowsFor(mode));
  emit('mode');
}

$('mode').addEventListener('click', (event) => {
  const button = (event.target as HTMLElement).closest<HTMLElement>('[data-mode]');
  if (button) setMode(button.dataset.mode as 'asm' | 'hla');
});

function goTo(addr: number): void {
  if (currentView !== 'listing') showView('listing');
  listing.goTo(addr);
}

function openReference(mnemonic: string): void {
  showView('reference');
  showReference(mnemonic);
}

function fillFunctions(): void {
  const p = state.program;
  if (!p) return;
  const host = $('fn-list');
  if (!fnList) {
    fnList = new VirtualList<Fn>(
      host,
      30,
      (fn) => {
        const name = fnName(fn);
        const split = name.lastIndexOf('::', name.endsWith('>') ? name.lastIndexOf('<') : name.length);
        const label = split > 0 && settings.names !== 'raw' ? `<span class="crate">${esc(name.slice(0, split + 2))}</span>${esc(name.slice(split + 2))}` : esc(name);
        return `<span class="fn-dot ${fn.kind}"></span><span class="fn-name" title="${esc(fn.full)}">${label}</span><span class="fn-addr">${fn.addr.toString(16)}</span>`;
      },
      (fn) => {
        if (fn.count) goTo(fn.addr);
        else select({ kind: 'import', name: fn.raw ?? fn.name, addr: fn.addr });
      },
    );
  }
  const exports = exportedAddresses(p);
  const exportChip = document.querySelector<HTMLElement>('#fn-kinds [data-kind=export]')!;
  exportChip.hidden = !exports.size;
  if (fnKind === 'export' && !exports.size) setFnKind('all');
  const needle = $<HTMLInputElement>('fn-filter').value.trim().toLowerCase();
  // A module's imported functions have no code: they are listed under Imports only.
  const imported = viewOf(p).imported;
  const all = imported && fnKind === 'import' ? imported : p.functions;
  const items = all.filter((fn) => {
    if (fnKind === 'named' && fn.kind === 'anonymous') return false;
    if (fnKind === 'import' && fn.kind !== 'import') return false;
    if (fnKind === 'export' && !exports.has(fn.addr)) return false;
    return !needle || fnName(fn).toLowerCase().includes(needle) || fn.addr.toString(16).includes(needle);
  });
  fnList.set(items);
  $('fn-count').textContent = n(items.length);
  markCurrentFunction();
}

let exported: { program: Disassembly; addrs: Set<number> } | null = null;

/**
 * Where the functions the program exports start. Not every one is listed as
 * an export: main is the entry point and a module's start function is too,
 * so the export tables are asked, not the kinds of the functions.
 */
function exportedAddresses(p: Disassembly): Set<number> {
  if (exported?.program === p) return exported.addrs;
  const addrs = viewOf(p).exports();
  exported = { program: p, addrs };
  return addrs;
}

function setFnKind(kind: string): void {
  fnKind = kind;
  for (const c of document.querySelectorAll<HTMLElement>('#fn-kinds .chip')) c.classList.toggle('is-on', c.dataset.kind === kind);
}

function markCurrentFunction(): void {
  const p = state.program;
  if (!p || !fnList) return;
  const sel = state.selection;
  let index = -1;
  if (sel?.kind === 'insn' || sel?.kind === 'label') index = p.functionOfIndex(sel.index);
  else if (sel?.kind === 'fn') index = sel.fn;
  const fn = p.functions[index];
  if (!fn) return;
  const needle = $<HTMLInputElement>('fn-filter').value.trim();
  if (needle || fnKind !== 'all') return;
  fnList.current = index;
  fnList.reveal(index);
}

$('fn-filter').addEventListener('input', fillFunctions);
$('fn-kinds').addEventListener('click', (event) => {
  const chip = (event.target as HTMLElement).closest<HTMLElement>('[data-kind]');
  if (!chip) return;
  setFnKind(chip.dataset.kind!);
  fillFunctions();
});
on('navigate', markCurrentFunction);
on('select', () => {
  if (window.matchMedia('(max-width: 1180px)').matches) $('workspace').classList.toggle('show-inspector', !!state.selection && settings.inspector && currentView !== 'listing');
});

$('back').addEventListener('click', () => listing.back());
$('forward').addEventListener('click', () => listing.forward());
on('navigate', () => {
  $<HTMLButtonElement>('back').disabled = !state.history.length;
  $<HTMLButtonElement>('forward').disabled = !state.future.length;
});

/* ------------------------------------------------------------------ *
 * Search and keys
 * ------------------------------------------------------------------ */

initInspector(goTo, openReference);
initPages(goTo, openReference, (name) => void openSlice(name));
initReference(goTo);
initPatch(goTo);
setAssembler(assemble);
initPalette({
  goTo,
  showString: (addr) => {
    select({ kind: 'string', addr });
    if (state.program && state.program.dataRefs.get(addr)?.length) {
      const first = state.program.dataRefs.get(addr)![0]!;
      goTo(first);
      select({ kind: 'string', addr });
    }
  },
  openReference,
});
$('search-open').addEventListener('click', () => openPalette());
installTooltips(document.body);
startServiceWorker();

document.addEventListener('click', (event) => {
  const link = (event.target as HTMLElement).closest('a[href="#"]');
  if (link) event.preventDefault();
});

document.addEventListener('keydown', (event) => {
  const typing = (event.target as HTMLElement).closest('input, select, textarea');
  const mod = isMac ? event.metaKey : event.ctrlKey;
  if (mod && event.key.toLowerCase() === 'k') {
    event.preventDefault();
    if ($('palette').hidden) openPalette();
    else closePalette();
    return;
  }
  if (event.key === 'Escape') {
    closePalette();
    $('picker').hidden = true;
    $('editor').hidden = true;
    $('menu').hidden = true;
    $('workspace').classList.remove('show-inspector');
    return;
  }
  if (!state.program) return;
  if (event.altKey && event.key === 'ArrowLeft') {
    event.preventDefault();
    listing.back();
    return;
  }
  if (event.altKey && event.key === 'ArrowRight') {
    event.preventDefault();
    listing.forward();
    return;
  }
  if (typing || mod || event.altKey || !$('palette').hidden) return;
  switch (event.key.toLowerCase()) {
    case 'a':
      setMode('asm');
      break;
    case 'h':
      setMode('hla');
      break;
    case 'g':
      event.preventDefault();
      openPalette('0x');
      break;
    case '/':
      event.preventDefault();
      $('fn-filter').focus();
      break;
    case 'x':
      $('workspace').classList.add('show-inspector');
      break;
    case 'e':
      if (state.selection?.kind === 'insn') openEditor(state.selection.index);
      break;
    default:
      return;
  }
});
