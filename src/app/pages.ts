/**
 * The pages next to the listing: statistics, strings, imports and exports, and the
 * Mach-O overview. Each is drawn when the program opens and redrawn only
 * when a setting it shows changes.
 */

import { language, n, t, tn } from '../core/i18n';
import type { MnemonicCount, StringRef } from '../core/program';
import { categoryLabel, fileTypeLabel, secondsLabel, sectionTypeLabel, sizeLabel } from './labels';
import { catalogue, fnName, importCallers, nativeProgram, program, select, state } from './state';
import { STT } from '../core/elf';
import type { Bundle } from '../core/archive';
import type { Objc } from '../core/objc';
import { renderElf } from './elf';
import { renderPe } from './pe';
import { $, esc, hex, toast, VirtualList } from './ui';
import { viewOf } from './views';

let goTo: (addr: number) => void = () => {};
let openReference: (mnemonic: string) => void = () => {};
let openSlice: (slice: string) => void = () => {};

export function initPages(navigate: (addr: number) => void, reference: (mnemonic: string) => void, slice: (name: string) => void): void {
  goTo = navigate;
  openReference = reference;
  openSlice = slice;
  // Links in the pages drawn as HTML: code, data, imported functions, the reference.
  for (const id of ['imports', 'overview']) {
    $(id).addEventListener('click', (event) => {
      const target = event.target as HTMLElement;
      const mem = target.closest<HTMLElement>('[data-mem]');
      if (mem) select({ kind: 'string', addr: Number(mem.dataset.mem) });
      const imp = target.closest<HTMLElement>('[data-import]');
      if (imp) select({ kind: 'import', name: '', addr: Number(imp.dataset.import) });
      const slice = target.closest<HTMLElement>('[data-slice]');
      if (slice) openSlice(slice.dataset.slice!);
    });
    $(id).addEventListener('dblclick', (event) => {
      const go = (event.target as HTMLElement).closest<HTMLElement>('[data-goto]');
      if (go) goTo(Number(go.dataset.goto));
    });
    $(id).addEventListener('click', (event) => {
      const go = (event.target as HTMLElement).closest<HTMLElement>('a[data-goto]');
      if (go) goTo(Number(go.dataset.goto));
    });
  }
}

const lookup = (mnemonic: string) => catalogue().lookup(mnemonic);
const catalogKey = (mnemonic: string) => catalogue().key(mnemonic);

const pct = (part: number, whole: number) => (whole ? (part / whole) * 100 : 0);
const fmtPct = (value: number) => {
  const digits = value >= 10 ? 1 : 2;
  if (value > 0 && value < 0.1) return `<${(0.1).toLocaleString(language())}`;
  return value.toLocaleString(language(), { minimumFractionDigits: digits, maximumFractionDigits: digits });
};
const size = sizeLabel;

/* ------------------------------------------------------------------ *
 * Statistics
 * ------------------------------------------------------------------ */

let joinConditions = false;
let statsFilter = '';

export function renderStats(): void {
  const p = program();
  const page = $('stats');
  const total = p.totalInstructions;
  const named = p.functions.filter((f) => f.kind !== 'anonymous').length;
  const view = viewOf(p);
  const unknown = p.counts.find((c) => c.mnemonic === view.unknown)?.count ?? 0;
  const imported = view.imported?.length ?? nativeProgram().image.imports.length;
  const codeBytes = view.codeBytes();
  const tiles = [
    [n(total), t('stats', 'instructions')],
    [n(p.counts.length), t('stats', 'different mnemonics')],
    [n(p.functions.length), tn('stats', 'functions, {count} with a name', 'functions, {count} with names', named)],
    [n(p.strings.length), t('stats', 'strings')],
    [n(imported), t('stats', 'imported symbols')],
    [size(codeBytes), t('stats', 'of code')],
    [secondsLabel(p.decodeMs / 1000), t('stats', 'to decode everything')],
    [n(unknown), view.unknownLabel()],
  ];

  // By category
  const categories = new Map<string, number>();
  for (const { mnemonic, count } of p.counts) {
    // Literal pools and switch tables among 32-bit Arm code are data, not undecoded instructions.
    const category = lookup(mnemonic)?.category ?? (/^\.(word|short|byte|long|quad)$/.test(mnemonic) ? 'data' : 'not decoded');
    categories.set(category, (categories.get(category) ?? 0) + count);
  }
  const cats = [...categories].sort((a, b) => b[1] - a[1]);
  const topCat = cats[0]?.[1] ?? 1;

  page.innerHTML = `
    <h2>${esc(t('stats', 'Statistics'))}</h2>
    <p class="lede">${esc(t('stats', 'Every instruction of the program, counted by mnemonic, from the most frequent down. Click a mnemonic to read about it and see where it is used.'))}</p>
    <div class="tiles">${tiles.map(([v, l]) => `<div class="tile"><div class="tile-value">${esc(v!)}</div><div class="tile-label">${esc(l!)}</div></div>`).join('')}</div>
    <h3>${esc(t('stats', 'By kind of work'))}</h3>
    <div class="cats">${cats
      .map(
        ([name, count]) =>
          `<div class="cat-row" data-tip="${esc(esc(`${categoryLabel(name)}: ${n(count)} (${fmtPct(pct(count, total))}%)`))}"><span>${esc(categoryLabel(name))}</span><div class="bar-track"><div class="bar-fill" style="width:${(count / topCat) * 100}%"></div></div><span class="bar-pct">${fmtPct(pct(count, total))}%</span></div>`,
      )
      .join('')}</div>
    <h3>${esc(t('stats', 'By mnemonic'))}</h3>
    <div class="stats-controls">
      <input id="stats-filter" class="field" type="search" placeholder="${esc(t('stats', 'Filter mnemonics'))}" value="${esc(statsFilter)}" spellcheck="false">
      <label class="toggle"${view.joinKey ? '' : ' hidden'}><input id="stats-join" type="checkbox"${joinConditions && view.joinKey ? ' checked' : ''}> ${esc(view.joinLabel())}</label>
      <button id="stats-copy" class="button" type="button">${esc(t('stats', 'Copy as CSV'))}</button>
    </div>
    <div id="stats-bars" class="bars" role="table"></div>`;

  const filter = $<HTMLInputElement>('stats-filter');
  filter.addEventListener('input', () => {
    statsFilter = filter.value;
    drawBars();
  });
  $<HTMLInputElement>('stats-join').addEventListener('change', (event) => {
    joinConditions = (event.target as HTMLInputElement).checked;
    drawBars();
  });
  $('stats-copy').addEventListener('click', () => {
    const lines = ['rank,mnemonic,count,percent,summary', ...counted().map((c, i) => `${i + 1},${c.mnemonic},${c.count},${pct(c.count, total).toFixed(4)},"${(lookup(c.mnemonic)?.summary ?? '').replace(/"/g, '""')}"`)];
    navigator.clipboard.writeText(`${lines.join('\n')}\n`).then(
      () => toast(t('stats', 'Statistics copied')),
      () => toast(t('stats', 'The browser did not allow copying')),
    );
  });
  $('stats-bars').addEventListener('click', (event) => {
    const row = (event.target as HTMLElement).closest<HTMLElement>('[data-mn]');
    if (row) openReference(catalogKey(row.dataset.mn!));
  });
  drawBars();
}

function counted(): MnemonicCount[] {
  const p = program();
  const keyOf = viewOf(p).joinKey;
  if (!joinConditions || !keyOf) return p.counts;
  const joined = new Map<string, number>();
  for (const { mnemonic, count } of p.counts) {
    const key = keyOf(mnemonic);
    joined.set(key, (joined.get(key) ?? 0) + count);
  }
  return [...joined].map(([mnemonic, count]) => ({ mnemonic, count })).sort((a, b) => b.count - a.count || a.mnemonic.localeCompare(b.mnemonic));
}

function drawBars(): void {
  const p = program();
  const total = p.totalInstructions;
  const all = counted();
  const top = all[0]?.count ?? 1;
  const needle = statsFilter.trim().toLowerCase();
  const head = `<div class="bar-row head" role="row"><span>#</span><span>${esc(t('stats', 'Mnemonic'))}</span><span>${esc(t('stats', 'What it does'))}</span><span></span><span style="text-align:right">${esc(t('stats', 'Count'))}</span><span style="text-align:right">%</span></div>`;
  const rows = all
    .map((c, i) => ({ c, i }))
    .filter(({ c }) => !needle || c.mnemonic.includes(needle) || (lookup(c.mnemonic)?.summary ?? '').toLowerCase().includes(needle))
    .map(({ c, i }) => {
      const entry = lookup(c.mnemonic);
      const share = pct(c.count, total);
      const tip = esc(`<b>${esc(c.mnemonic)}</b> — ${n(c.count)} (${fmtPct(share)}%)${entry ? `<span class="tt-sub">${esc(entry.summary)}</span>` : ''}`);
      return `<div class="bar-row" role="row" data-mn="${esc(c.mnemonic)}" data-tip="${tip}"><span class="bar-rank">${i + 1}</span><span class="bar-mn">${esc(c.mnemonic)}</span><span class="bar-sum">${esc(entry?.summary ?? (/^\.(word|short|byte|long|quad)$/.test(c.mnemonic) ? t('stats', 'data among the instructions: literal pools, switch tables') : ''))}</span><div class="bar-track"><div class="bar-fill" style="width:${(c.count / top) * 100}%"></div></div><span class="bar-count">${n(c.count)}</span><span class="bar-pct">${fmtPct(share)}</span></div>`;
    })
    .join('');
  $('stats-bars').innerHTML = head + rows;
}

/* ------------------------------------------------------------------ *
 * Strings
 * ------------------------------------------------------------------ */

let stringList: VirtualList<StringRef> | null = null;

export function renderStrings(): void {
  const p = program();
  const host = $('string-list');
  const input = $<HTMLInputElement>('string-filter');
  stringList = new VirtualList<StringRef>(
    host,
    28,
    (s) =>
      `<span class="s-addr">${s.addr.toString(16)}</span><span class="s-sect">${esc(s.section)}</span><span class="s-text">${esc(JSON.stringify(s.text.length > 300 ? `${s.text.slice(0, 300)}…` : s.text))}</span><span class="s-refs">${(p.dataRefs.get(s.addr)?.length ?? 0) || ''}</span>`,
    (s, index, event) => {
      if (stringList) {
        stringList.current = index;
        stringList.refresh();
      }
      select({ kind: 'string', addr: s.addr });
      if (event.detail === 2) {
        const first = p.dataRefs.get(s.addr)?.[0];
        if (first !== undefined) goTo(first);
      }
    },
  );
  const apply = () => {
    const needle = input.value.toLowerCase();
    const items = needle ? p.strings.filter((s) => s.text.toLowerCase().includes(needle)) : p.strings;
    stringList!.set(items);
    $('string-count').textContent = tn('strings', '{count} string', '{count} strings', items.length);
  };
  input.value = '';
  input.oninput = apply;
  apply();
}

/* ------------------------------------------------------------------ *
 * Imports
 * ------------------------------------------------------------------ */

export function renderImports(): void {
  const page = $('imports');
  const own = viewOf(program()).renderImports;
  if (own) {
    own(page);
    return;
  }
  const p = nativeProgram();
  const stubByName = new Map<string, number>();
  for (const fn of p.functions) if (fn.kind === 'import' && fn.raw) stubByName.set(fn.raw, fn.addr);
  const seen = new Set<string>();
  const imports = p.image.imports
    .filter((imp) => (seen.has(imp.name) ? false : (seen.add(imp.name), true)))
    .map((imp) => {
      const stub = stubByName.get(imp.name) ?? stubByName.get(`_${imp.name}`);
      // Code may also call an import through its slot, without a stub (`call qword ptr [rip + …]`, `blr x8`).
      const calls = importCallers(p, imp.name, stub).length;
      return { imp, stub, calls };
    })
    .sort((a, b) => b.calls - a.calls || a.imp.name.localeCompare(b.imp.name));
  const libraries = new Map<string, number>();
  for (const { imp } of imports) libraries.set(imp.library, (libraries.get(imp.library) ?? 0) + 1);
  const short = (lib: string) => lib.split('/').pop() ?? lib;
  // Every name the page shows, read back to source in one call to the core.
  p.image.demangleAll(imports.map(({ imp }) => imp.name));
  const exports = nativeExports();
  page.innerHTML = `
    <h2>${esc(exports.length ? t('imports', 'Imports and exports') : t('imports', 'Imports'))}</h2>
    <p class="lede">${esc(t('imports', 'What the program takes from the system: the libraries it links against and the functions and data it uses from them, with how many places call each.'))}${exports.length ? ` ${esc(t('imports', 'And what it offers to others: the symbols it exports, with how many places in its own code call each.'))}` : ''}</p>
    <h3>${esc(tn('imports', '{count} library', '{count} libraries', p.image.libraries.length))}</h3>
    <table class="table"><thead><tr><th>${esc(t('imports', 'Library'))}</th><th>${esc(t('imports', 'Symbols'))}</th></tr></thead><tbody>
    ${p.image.libraries.map((lib) => `<tr><td class="mono">${esc(lib)}</td><td class="mono">${libraries.get(lib) ?? 0}</td></tr>`).join('')}
    </tbody></table>
    <h3>${esc(tn('imports', '{count} symbol', '{count} symbols', imports.length))}</h3>
    <table class="table" id="import-table"><thead><tr><th>${esc(t('imports', 'Name'))}</th><th>${esc(t('imports', 'Library'))}</th><th style="text-align:right">${esc(t('imports', 'Calls'))}</th></tr></thead><tbody>
    ${imports
      .map(
        ({ imp, stub, calls }) =>
          `<tr class="clickable" data-name="${esc(imp.name)}"${stub !== undefined ? ` data-stub="${stub}"` : ''}><td class="mono" title="${esc(imp.name)}">${esc(p.image.demangle(imp.name).full)}${imp.version ? ` <span class="hint">@${esc(imp.version)}</span>` : ''}${imp.weak ? ` <span class="tag">${esc(t('imports', 'weak'))}</span>` : ''}</td><td class="mono">${esc(short(imp.library) || '—')}</td><td class="mono" style="text-align:right">${calls || ''}</td></tr>`,
      )
      .join('')}
    </tbody></table>
    ${exports.length ? exportsHtml(exports) : ''}`;
  $('import-table').addEventListener('click', (event) => {
    const row = (event.target as HTMLElement).closest<HTMLElement>('tr[data-name]');
    if (!row) return;
    const stub = row.dataset.stub ? Number(row.dataset.stub) : undefined;
    select({ kind: 'import', name: row.dataset.name!, addr: stub });
  });
  $('import-table').addEventListener('dblclick', (event) => {
    const row = (event.target as HTMLElement).closest<HTMLElement>('tr[data-stub]');
    if (row) goTo(Number(row.dataset.stub));
  });
  page.querySelector('#export-table')?.addEventListener('click', (event) => {
    const row = (event.target as HTMLElement).closest<HTMLElement>('tr[data-fn]');
    if (row) select({ kind: 'fn', fn: Number(row.dataset.fn) });
  });
}

interface NativeExport {
  raw: string;
  addr: number;
  /** An index into the program's functions, when the symbol names code. */
  fn?: number;
  kind: string;
  /** Data the strings card can show. */
  data?: boolean;
  calls: number;
  size?: number;
  version?: string;
  weak?: boolean;
}

/**
 * What a Mach-O file's export trie or an ELF file's dynamic symbols offer.
 * Mach-O re-exports (a symbol passed on from another library) have no
 * address here and are left out by the parser.
 */
function nativeExports(): NativeExport[] {
  const p = nativeProgram();
  const index = new Map(p.functions.map((fn, i) => [fn, i]));
  const code = (addr: number) => {
    const fn = p.functionAt(addr);
    return fn && fn.addr === addr ? index.get(fn) : undefined;
  };
  const calls = (addr: number) => p.callers.get(addr)?.length ?? 0;
  const out: NativeExport[] = [];
  const elf = p.image.elf;
  const pe = p.image.pe;
  if (pe) {
    for (const e of pe.exports) {
      const fn = e.forwarder ? undefined : code(e.addr);
      const kind = e.forwarder ? t('imports', 'forwarded to {target}', { target: e.forwarder }) : fn !== undefined ? t('imports', 'function') : t('imports', 'data');
      out.push({ raw: e.name, addr: e.addr, fn, kind, data: !e.forwarder && fn === undefined, calls: e.forwarder ? 0 : calls(e.addr) });
    }
  } else if (elf) {
    for (const e of elf.exports) {
      const func = e.type === STT.FUNC || e.type === STT.GNU_IFUNC;
      const kind = func ? t('imports', 'function') + (e.thumb ? ' · T32' : p.arch === 'arm32' ? ' · A32' : '') : e.type === STT.OBJECT ? t('imports', 'data') : e.type === STT.TLS ? t('imports', 'thread-local') : '';
      out.push({ raw: e.name, addr: e.addr, fn: func ? code(e.addr) : undefined, kind, data: e.type === STT.OBJECT, calls: calls(e.addr), size: e.size || undefined, version: e.version });
    }
  } else {
    for (const e of p.image.macho?.exports ?? []) {
      // The low two bits of the flags: regular, thread-local, absolute; 4 is a weak definition.
      const type = e.flags & 3;
      const fn = type === 0 ? code(e.addr) : undefined;
      const kind = type === 1 ? t('imports', 'thread-local') : type === 2 ? t('imports', 'absolute') : fn !== undefined ? t('imports', 'function') : t('imports', 'data');
      out.push({ raw: e.name, addr: e.addr, fn, kind, data: type === 0 && fn === undefined, calls: calls(e.addr), weak: !!(e.flags & 4) });
    }
  }
  return out.sort((a, b) => b.calls - a.calls || a.raw.localeCompare(b.raw));
}

/** A library can export tens of thousands of symbols; the table shows the first of them. */
const EXPORT_ROWS = 5000;

function exportsHtml(exports: NativeExport[]): string {
  const p = nativeProgram();
  p.image.demangleAll(exports.slice(0, EXPORT_ROWS).map((e) => e.raw));
  // A Mach-O export trie says nothing of sizes.
  const sized = exports.some((e) => e.size !== undefined);
  const row = (e: NativeExport) => {
    const attr = e.fn !== undefined ? ` class="clickable" data-fn="${e.fn}" data-goto="${e.addr}"` : e.data ? ` class="clickable" data-mem="${e.addr}"` : '';
    return `<tr${attr}><td class="mono" title="${esc(e.raw)}">${esc(p.image.demangle(e.raw).full)}${e.version ? ` <span class="hint">@${esc(e.version)}</span>` : ''}${e.weak ? ` <span class="tag">${esc(t('imports', 'weak'))}</span>` : ''}</td><td class="mono">${hex(e.addr)}</td>${sized ? `<td class="mono" style="text-align:right">${e.size ?? ''}</td>` : ''}<td>${esc(e.kind)}</td><td class="mono" style="text-align:right">${e.calls || ''}</td></tr>`;
  };
  return `
    <h3>${esc(tn('imports', '{count} export', '{count} exports', exports.length))}${exports.length > EXPORT_ROWS ? ` <span class="hint">${esc(t('imports', 'the first {count} are shown; the function list finds the rest', { count: n(EXPORT_ROWS) }))}</span>` : ''}</h3>
    <table class="table" id="export-table"><thead><tr><th>${esc(t('imports', 'Name'))}</th><th>${esc(t('imports', 'Address'))}</th>${sized ? `<th style="text-align:right">${esc(t('imports', 'Size'))}</th>` : ''}<th>${esc(t('imports', 'Kind'))}</th><th style="text-align:right">${esc(t('imports', 'Calls'))}</th></tr></thead><tbody>
    ${exports.slice(0, EXPORT_ROWS).map(row).join('')}
    </tbody></table>`;
}

/* ------------------------------------------------------------------ *
 * Mach-O overview
 * ------------------------------------------------------------------ */

/** Links that open the other slices of a universal file this disassembler reads. */
function slicesHtml(image: NonNullable<ReturnType<typeof nativeProgram>['image']['macho']>): string {
  const others = image.arches.filter((a) => a.name !== image.arch && /^(arm64e?|x86_64|i386|armv7[sk]?|arm)$/.test(a.name));
  return others.map((a) => `<a href="#" data-slice="${esc(a.name)}">${esc(t('overview', 'Open the {arch} slice', { arch: a.name }))}</a>`).join(' · ');
}

/** Where the program came from when it was taken out of an app: the bundle, and who signed it for which devices. */
function bundleRows(bundle: Bundle): [string, string][] {
  const date = (d: Date | undefined) => (d ? d.toLocaleDateString(language(), { year: 'numeric', month: 'long', day: 'numeric' }) : '');
  const version = bundle.version && bundle.build && bundle.build !== bundle.version ? `${bundle.version} (${bundle.build})` : bundle.version ?? bundle.build;
  const profile = bundle.profile;
  const devices = profile ? (profile.allDevices ? t('overview', 'any device') : profile.devices !== undefined ? tn('overview', '{count} device', '{count} devices', profile.devices) : t('overview', 'App Store')) : '';
  return [
    [t('overview', 'Bundle'), `${bundle.path}${bundle.identifier ? ` · ${bundle.identifier}` : ''}`],
    ...(version ? [[t('overview', 'Version'), version] as [string, string]] : []),
    ...(bundle.minimumOS ? [[t('overview', 'Runs on'), `${bundle.platforms?.length ? `${bundle.platforms.join(', ')} ` : ''}${bundle.minimumOS}+`] as [string, string]] : []),
    ...(profile
      ? [
          [t('overview', 'Provisioning profile'), [profile.name, profile.team ? `${profile.team}${profile.teamId ? ` (${profile.teamId})` : ''}` : profile.teamId].filter(Boolean).join(' · ')] as [string, string],
          [t('overview', 'Profile allows'), [devices, profile.debuggable ? t('overview', 'debugging') : '', profile.expires ? t('overview', 'until {date}', { date: date(profile.expires) }) : ''].filter(Boolean).join(' · ')] as [string, string],
        ]
      : []),
  ];
}

/** A program can have tens of thousands of classes; the table shows the first of them. */
const CLASS_ROWS = 5000;

/** The Objective-C classes and categories, each with where its first method is. */
function objcHtml(objc: Objc): string {
  const p = nativeProgram();
  const all = [...objc.classes, ...objc.categories];
  if (!all.length && !objc.selrefs.size) return '';
  const methods = all.reduce((sum, c) => sum + c.methods.length, 0);
  const row = (c: Objc['classes'][number]) => {
    const first = c.methods.find((m) => m.imp && p.functionAt(m.imp)?.addr === m.imp);
    const attr = first ? ` class="clickable" data-goto="${first.imp}"` : '';
    const name = c.category !== undefined ? `${c.swift ?? c.name} (${c.category})` : c.swift ?? c.name;
    return `<tr${attr}><td class="mono"${c.swift ? ` title="${esc(c.name)}"` : ''}>${esc(name)}</td><td class="mono">${esc(c.superclass ?? '')}</td><td class="mono" style="text-align:right">${c.methods.length}</td></tr>`;
  };
  return `
    <h3>${esc(t('overview', 'Objective-C'))}</h3>
    <p class="hint">${esc(
      [
        tn('overview', '{count} class', '{count} classes', objc.classes.length),
        tn('overview', '{count} category', '{count} categories', objc.categories.length),
        tn('overview', '{count} method', '{count} methods', methods),
        tn('overview', '{count} protocol', '{count} protocols', objc.protocols.length),
        tn('overview', '{count} selector reference', '{count} selector references', objc.selrefs.size),
        tn('overview', '{count} string constant', '{count} string constants', objc.cfstrings.size),
      ].join(' · '),
    )}${all.length > CLASS_ROWS ? ` · ${esc(t('overview', 'the first {count} classes are shown', { count: n(CLASS_ROWS) }))}` : ''}</p>
    ${all.length ? `<table class="table" id="objc-table"><thead><tr><th>${esc(t('overview', 'Class'))}</th><th>${esc(t('overview', 'Superclass'))}</th><th style="text-align:right">${esc(t('overview', 'Methods'))}</th></tr></thead><tbody>
    ${all.slice(0, CLASS_ROWS).map(row).join('')}
    </tbody></table>` : ''}`;
}

const prot = (v: number) => `${v & 1 ? 'r' : '-'}${v & 2 ? 'w' : '-'}${v & 4 ? 'x' : '-'}`;

export function renderOverview(): void {
  const page = $('overview');
  const own = viewOf(program()).renderOverview;
  if (own) {
    own(page);
    return;
  }
  const native = nativeProgram();
  if (native.image.pe) {
    renderPe(native as Parameters<typeof renderPe>[0], page);
    return;
  }
  if (!native.image.macho) {
    renderElf(native, page);
    return;
  }
  const p = native;
  const image = native.image.macho;
  const entry = image.entry !== undefined ? p.functionAt(image.entry) : undefined;
  const info: [string, string][] = [
    [t('overview', 'File'), `${state.fileName} · ${size(state.fileSize)}`],
    ...(state.bundle ? bundleRows(state.bundle) : []),
    [t('overview', 'Architecture'), image.arches.length > 1 ? `${image.arch} (${t('overview', 'universal file')}: ${image.arches.map((a) => a.name).join(', ')})` : image.arch],
    ...(slicesHtml(image) ? [[t('overview', 'Other slices'), slicesHtml(image)] as [string, string]] : []),
    [t('overview', 'Type'), fileTypeLabel(image.filetype, image.fileTypeName)],
    image.build ? [t('overview', 'Platform'), `${image.build.platform} ${image.build.minos}+, SDK ${image.build.sdk}`] : null,
    image.build?.tools.length ? [t('overview', 'Built with'), image.build.tools.join(', ')] : null,
    image.uuid ? ['UUID', image.uuid] : null,
    image.entry !== undefined ? [t('overview', 'Entry point'), `${hex(image.entry)}${entry ? ` (${fnName(entry)})` : ''}`] : null,
    image.installName ? [t('overview', 'Install name'), image.installName] : null,
    image.sourceVersion ? [t('overview', 'Source version'), image.sourceVersion] : null,
    image.signature?.identifier ? [t('overview', 'Signed as'), `${image.signature.identifier}${image.signature.teamId ? ` · team ${image.signature.teamId}` : ` · ${t('overview', 'ad hoc (no team)')}`}`] : null,
    image.signature?.hashType ? [t('overview', 'Signature'), `${image.signature.hashType}, ${tn('overview', '{count} page', '{count} pages', image.signature.pages ?? 0)}`] : null,
    image.encryption ? [t('overview', 'Encrypted'), image.encrypted ? t('overview', 'yes') : t('overview', 'no (decrypted, or never encrypted)')] : null,
    [t('overview', 'Header flags'), image.flagNames.join(' ')],
  ].filter(Boolean) as [string, string][];

  page.innerHTML = `
    <h2>${esc(t('overview', 'Mach-O'))}</h2>
    <p class="lede">${esc(t('overview', 'The container around the code: how the program is laid out in memory, what it needs to start, and how it is signed.'))}</p>
    <dl class="kv" style="max-width:900px">${info.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${k === t('overview', 'Other slices') ? v : esc(v)}</dd>`).join('')}</dl>
    ${native.image.objc ? objcHtml(native.image.objc) : ''}
    <h3>${esc(t('overview', 'Segments and sections'))}</h3>
    <table class="table"><thead><tr><th>${esc(t('overview', 'Segment'))}</th><th>${esc(t('overview', 'Section'))}</th><th>${esc(t('overview', 'Address'))}</th><th>${esc(t('overview', 'Size'))}</th><th>${esc(t('overview', 'File offset'))}</th><th>${esc(t('overview', 'Kind'))}</th></tr></thead><tbody>
    ${image.segments
      .map(
        (seg) =>
          `<tr><td class="mono"><b>${esc(seg.name)}</b></td><td class="mono">${esc(prot(seg.initprot))}</td><td class="mono">${hex(seg.vmaddr)}</td><td class="mono">${size(seg.vmsize)}</td><td class="mono">${hex(seg.fileoff)}</td><td></td></tr>` +
          seg.sections
            .map(
              (s) =>
                `<tr><td></td><td class="mono">${esc(s.sectname)}</td><td class="mono">${hex(s.addr)}</td><td class="mono">${size(s.size)}</td><td class="mono">${s.offset ? hex(s.offset) : '—'}</td><td>${esc(sectionTypeLabel(s.flags & 0xff))}${s.flags & 0x80000000 ? ` · ${esc(t('overview', 'code'))}` : ''}</td></tr>`,
            )
            .join(''),
      )
      .join('')}
    </tbody></table>
    <h3>${esc(tn('overview', '{count} load command', '{count} load commands', image.commands.length))}</h3>
    <table class="table"><thead><tr><th>${esc(t('overview', 'Command'))}</th><th>${esc(t('overview', 'Size'))}</th><th>${esc(t('overview', 'What it says'))}</th></tr></thead><tbody>
    ${image.commands.map((c) => `<tr><td class="mono">${esc(c.name)}</td><td class="mono">${c.size}</td><td class="mono">${esc(c.summary)}</td></tr>`).join('')}
    </tbody></table>
    ${image.rpaths.length ? `<h3>${esc(t('overview', 'Run-path search paths'))}</h3><div class="pre">${esc(image.rpaths.join('\n'))}</div>` : ''}
    <h3>${esc(t('overview', 'Entitlements'))}</h3>
    ${image.signature?.entitlements ? `<div class="pre">${esc(image.signature.entitlements)}</div>` : `<p class="hint">${esc(t('overview', 'The signature carries no entitlements.'))}</p>`}
  `;
}
