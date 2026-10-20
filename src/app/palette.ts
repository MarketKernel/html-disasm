/**
 * Search everything from one box (⌘K / Ctrl+K): functions, imports,
 * strings, instructions of the reference, and addresses — typed as hex.
 */

import { t } from '../core/i18n';
import { catalogue, fnName, isWasm, program, select, state } from './state';
import { $, esc, hex } from './ui';
import { viewOf } from './views';

interface Result {
  kind: string;
  text: string;
  addr?: number;
  run: () => void;
}

export interface PaletteActions {
  goTo(addr: number): void;
  showString(addr: number): void;
  openReference(mnemonic: string): void;
}

let results: Result[] = [];
let active = 0;
let actions: PaletteActions;

export function initPalette(a: PaletteActions): void {
  actions = a;
  const overlay = $('palette');
  const input = $<HTMLInputElement>('palette-input');
  input.addEventListener('input', () => search(input.value));
  input.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown') active = Math.min(results.length - 1, active + 1);
    else if (event.key === 'ArrowUp') active = Math.max(0, active - 1);
    else if (event.key === 'Enter') {
      const result = results[active];
      closePalette();
      result?.run();
      return;
    } else if (event.key === 'Escape') {
      closePalette();
      return;
    } else return;
    event.preventDefault();
    draw();
  });
  overlay.addEventListener('mousedown', (event) => {
    if (event.target === overlay) closePalette();
  });
  $('palette-results').addEventListener('click', (event) => {
    const item = (event.target as HTMLElement).closest<HTMLElement>('[data-i]');
    if (!item) return;
    const result = results[Number(item.dataset.i)];
    closePalette();
    result?.run();
  });
}

export function openPalette(prefill = ''): void {
  if (!state.program) return;
  $('palette').hidden = false;
  const input = $<HTMLInputElement>('palette-input');
  input.value = prefill;
  search(prefill);
  input.focus();
  input.setSelectionRange(prefill.length, prefill.length);
}

export function closePalette(): void {
  $('palette').hidden = true;
}

function search(query: string): void {
  const p = program();
  const q = query.trim();
  const needle = q.toLowerCase();
  results = [];
  active = 0;
  if (/^(0x)?[0-9a-f]{4,16}$/i.test(q) || /^0x[0-9a-f]{1,3}$/i.test(q)) {
    const addr = parseInt(q.replace(/^0x/i, ''), 16);
    if (p.indexOf(addr) >= 0) results.push({ kind: t('palette', 'Address'), text: t('palette', 'Go to {addr}', { addr: hex(addr) }), addr, run: () => actions.goTo(addr) });
    // In a module code is addressed by file offset and data by memory address: the same number can be both.
    if ((p.indexOf(addr) < 0 || isWasm(p)) && p.dataAt(addr)) results.push({ kind: t('palette', 'Data'), text: hex(addr), addr, run: () => actions.showString(addr) });
  }
  if (!needle) {
    draw();
    return;
  }
  const prefix: Result[] = [];
  const inner: Result[] = [];
  for (const fn of p.functions) {
    const name = fnName(fn);
    const lower = name.toLowerCase();
    const at = lower.indexOf(needle);
    if (at < 0 && !(fn.raw && fn.raw.toLowerCase().includes(needle))) continue;
    const result = { kind: fn.kind === 'import' ? t('palette', 'Import') : t('palette', 'Function'), text: name, addr: fn.addr, run: () => actions.goTo(fn.addr) };
    const last = lower.lastIndexOf('::');
    (at === 0 || at === last + 2 ? prefix : inner).push(result);
    if (prefix.length > 40) break;
  }
  // The imported functions and members of a module, assembly or class have no code: choosing one shows it in the details panel.
  const view = viewOf(p);
  for (const member of view.imported ?? []) {
    if (prefix.length + inner.length > 60) break;
    const text = view.importText(member);
    if (!text.toLowerCase().includes(needle)) continue;
    inner.push({ kind: t('palette', 'Import'), text, run: () => select({ kind: 'import', name: member.raw ?? member.name, addr: member.addr }) });
  }
  results.push(...prefix.slice(0, 30), ...inner.slice(0, Math.max(0, 30 - prefix.length)));
  const instructions = catalogue();
  for (const key of instructions.mnemonics()) {
    if (results.length > 60) break;
    if (key === needle || (needle.length > 1 && key.startsWith(needle))) {
      results.push({ kind: t('palette', 'Instruction'), text: `${key} — ${instructions.lookup(key)?.summary ?? ''}`, run: () => actions.openReference(key) });
    }
  }
  let strings = 0;
  for (const s of p.strings) {
    if (strings >= 15) break;
    if (!s.text.toLowerCase().includes(needle)) continue;
    strings++;
    results.push({ kind: t('palette', 'String'), text: JSON.stringify(s.text.length > 90 ? `${s.text.slice(0, 90)}…` : s.text), addr: s.addr, run: () => actions.showString(s.addr) });
  }
  draw();
}

function draw(): void {
  const host = $('palette-results');
  if (!results.length) {
    host.innerHTML = `<div class="palette-item"><span class="palette-text hint">${esc(t('palette', 'Nothing found'))}</span></div>`;
    return;
  }
  host.innerHTML = results
    .map(
      (r, i) =>
        `<div class="palette-item${i === active ? ' is-active' : ''}" data-i="${i}" role="option" aria-selected="${i === active}"><span class="palette-kind">${esc(r.kind)}</span><span class="palette-text">${esc(r.text)}</span>${r.addr !== undefined ? `<span class="palette-addr">${r.addr.toString(16)}</span>` : ''}</div>`,
    )
    .join('');
  host.querySelector('.is-active')?.scrollIntoView({ block: 'nearest' });
}
