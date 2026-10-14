/**
 * The reference: every A64 instruction of the catalogue, and the HLA64
 * vocabulary the HLA64 view writes in. An instruction's page shows our
 * description, its forms and syntax with links to Arm's documentation, and
 * — when a program is open — how often and where the program uses it.
 */

import { conditions, type Word } from '../core/catalog';
import { categoryLabel, flagsLabel, groupHeading, groupLabel } from './labels';
import { n, t, tn } from '../core/i18n';
import { catalogue, fnName, state } from './state';
import { $, esc, h, VirtualList } from './ui';

type Item = { type: 'words' } | { type: 'group'; label: string } | { type: 'mn'; key: string; used: number };

let list: VirtualList<Item> | null = null;
let current: string = 'words';
let onlyUsed = false;
let goTo: (addr: number) => void = () => {};
let main: HTMLElement;
let filterInput: HTMLInputElement;

const lookup = (key: string) => catalogue().lookup(key);
const catalogKey = (mnemonic: string) => catalogue().key(mnemonic);

export function initReference(navigate: (addr: number) => void): void {
  goTo = navigate;
  const host = $('reference');
  filterInput = h('input', { class: 'field', type: 'search', placeholder: t('reference', 'Find an instruction'), spellcheck: 'false', autocomplete: 'off' });
  const allChip = h('button', { type: 'button', class: 'chip is-on' }, t('reference', 'All'));
  const usedChip = h('button', { type: 'button', class: 'chip' }, t('reference', 'In this program'));
  const setUsed = (value: boolean) => {
    onlyUsed = value;
    allChip.classList.toggle('is-on', !value);
    usedChip.classList.toggle('is-on', value);
    fill();
  };
  allChip.addEventListener('click', () => setUsed(false));
  usedChip.addEventListener('click', () => setUsed(true));
  const listHost = h('div', { class: 'vlist' });
  const side = h(
    'div',
    { class: 'ref-side' },
    h('div', { class: 'sidebar-head' }, h('div', { class: 'sidebar-title' }, t('reference', 'Reference'), h('span', { class: 'count', id: 'ref-count' })), filterInput, h('div', { class: 'chips' }, allChip, usedChip)),
    listHost,
  );
  main = h('div', { class: 'ref-main' });
  host.replaceChildren(side, main);
  list = new VirtualList<Item>(listHost, 30, renderItem, (item) => {
    if (item.type === 'group') return;
    show(item.type === 'words' ? 'words' : item.key);
  });
  filterInput.addEventListener('input', fill);
  main.addEventListener('click', (event) => {
    const go = (event.target as HTMLElement).closest<HTMLElement>('[data-goto]');
    if (go) goTo(Number(go.dataset.goto));
    const ref = (event.target as HTMLElement).closest<HTMLElement>('[data-ref]');
    if (ref) show(ref.dataset.ref!);
  });
  fill();
  show('words');
}

function usage(): Map<string, number> {
  const used = new Map<string, number>();
  for (const { mnemonic, count } of state.program?.counts ?? []) {
    const key = catalogKey(mnemonic);
    used.set(key, (used.get(key) ?? 0) + count);
  }
  return used;
}

function renderItem(item: Item): string {
  if (item.type === 'words') return `<span class="fn-dot export"></span><span class="fn-name"><b>${esc(t('reference', 'HLA64 vocabulary'))}</b></span>`;
  if (item.type === 'group') return `<span class="ref-group">${esc(item.label)}</span>`;
  const entry = lookup(item.key);
  return `<span class="bar-mn" style="min-width:9ch">${esc(item.key)}</span><span class="fn-name" style="color:var(--text-2)">${esc(entry?.summary ?? '')}</span>${item.used ? `<span class="mn-used">${n(item.used)}</span>` : ''}`;
}

/** Fills the list: the vocabulary first, then the instructions by group. */
export function fill(): void {
  if (!list) return;
  const needle = filterInput.value.trim().toLowerCase();
  const used = usage();
  const items: Item[] = needle ? [] : [{ type: 'words' }];
  let shown = 0;
  for (const group of catalogue().groups) {
    const keys = catalogue().mnemonics().filter((key) => {
      const entry = lookup(key)!;
      if (entry.group !== group) return false;
      if (onlyUsed && !used.get(key)) return false;
      // The summary is searched in the interface language and in English.
      return !needle || key.includes(needle) || entry.summary.toLowerCase().includes(needle) || catalogue().lookupEnglish(key)!.summary.toLowerCase().includes(needle);
    });
    if (!keys.length) continue;
    if (onlyUsed) keys.sort((a, b) => (used.get(b) ?? 0) - (used.get(a) ?? 0));
    items.push({ type: 'group', label: groupHeading(group) });
    for (const key of keys) items.push({ type: 'mn', key, used: used.get(key) ?? 0 });
    shown += keys.length;
  }
  list.set(items);
  $('ref-count').textContent = n(shown);
  // Another architecture's program: what was shown may not be in this catalogue, and the words change.
  if (main && shownFor !== catalogue().arch) show(current !== 'words' && lookup(current) ? current : 'words');
}

let shownFor = '';

export function show(key: string): void {
  current = key;
  shownFor = catalogue().arch;
  if (key === 'words') {
    main.innerHTML = wordsPage();
    main.scrollTop = 0;
    return;
  }
  const entry = lookup(key);
  if (!entry) {
    main.innerHTML = `<h2 class="mono">${esc(key)}</h2><p class="lede">${esc(t('reference', 'This is not in the catalogue.'))}</p>`;
    return;
  }
  const forms = entry.forms
    .map(
      (form) =>
        `<div class="form-head">${esc(form.heading)}${form.aliasOf ? ` <span class="hint">${esc(t('reference', 'alias of {name}', { name: form.aliasOf }))}</span>` : ''} <a href="${esc(catalogue().docUrl(form))}" target="_blank" rel="noopener noreferrer">${esc(catalogue().arch === 'wasm' ? t('reference', 'WebAssembly specification') : catalogue().arch === 'cil' ? (form.url.includes('learn.microsoft.com') ? 'Microsoft Learn' : 'ECMA-335') : catalogue().arch === 'jvm' ? t('reference', 'JVM specification') : catalogue().arch === 'x86' ? t('reference', 'x86 reference') : t('reference', 'Arm documentation'))} ↗</a></div>${form.syntax.map((s) => `<div class="syntax">${esc(s)}</div>`).join('')}`,
    )
    .join('');
  const conditionTable = key.endsWith('.cond')
    ? `<h3>${esc(t('reference', 'Conditions'))}</h3><table class="table"><tbody>${Object.entries(conditions())
        .map(([c, info]) => `<tr><td class="mono">${key.replace('cond', c)}</td><td>${esc(info.name)}</td><td class="mono">${esc(info.flags)}</td><td class="mono">${esc(info.hla ? (info.unsigned ? `a ${info.hla}u b` : info.zero ? `r ${info.hla} 0` : `a ${info.hla} b`) : '')}</td></tr>`)
        .join('')}</tbody></table>`
    : '';
  main.innerHTML = `
    <h2><span class="insn-mn">${esc(key)}</span></h2>
    <p class="insn-summary">${esc(entry.summary)}</p>
    <div class="tags"><span class="tag">${esc(categoryLabel(entry.category))}</span><span class="tag">${esc(groupLabel(entry.group))}</span>${entry.flags !== 'none' ? `<span class="tag">${esc(flagsLabel(entry.flags))}</span>` : ''}</div>
    <p class="lede">${esc(entry.description)}</p>
    ${entry.operation && entry.operation !== '—' ? `<div class="insn-text">${esc(entry.operation)}</div>` : ''}
    ${entry.stack ? `<p class="hint">${esc(t('reference', 'Stack'))}: <span class="mono">${esc(entry.stack)}</span></p>` : ''}
    ${conditionTable}
    <h3>${esc(t('reference', 'Forms'))}</h3>${forms}
    ${places(key)}
    <p class="hint" style="margin-top:24px">${esc(catalogue().arch === 'wasm' ? t('reference', 'Descriptions are written for this disassembler; the WebAssembly specification is the authoritative text.') : catalogue().arch === 'cil' ? t('reference', 'Descriptions are written for this disassembler; ECMA-335 (Partition III) is the authoritative text.') : catalogue().arch === 'jvm' ? t('reference', 'Descriptions are written for this disassembler; the Java Virtual Machine Specification (chapter 6) is the authoritative text.') : catalogue().arch === 'x86' ? t('reference', 'Descriptions are written for this disassembler; the forms are LLVM\'s, and the Intel and AMD manuals are the authoritative text.') : t('reference', 'Descriptions are written for this disassembler; the Arm documentation is the authoritative text.'))}</p>`;
  main.scrollTop = 0;
}

/** Where the open program uses a mnemonic: the first few hundred places. */
function places(key: string): string {
  const p = state.program;
  if (!p) return '';
  const ids = new Set<number>();
  p.mnemonics.forEach((m, id) => {
    if (catalogKey(m) === key) ids.add(id);
  });
  if (!ids.size) return `<h3>${esc(t('reference', 'In this program'))}</h3><p class="hint">${esc(t('reference', 'The program does not use it.'))}</p>`;
  const found: number[] = [];
  let total = 0;
  const idsArray = p.mnemonicIds;
  for (let i = 0; i < idsArray.length; i++) {
    if (!ids.has(idsArray[i]!)) continue;
    total++;
    if (found.length < 300) found.push(i);
  }
  const rows = found
    .map((i) => {
      const addr = p.addrOf(i);
      const fn = p.functions[p.functionOfIndex(i)];
      return `<div class="ref" data-goto="${addr}"><span>${addr.toString(16)}</span><span class="ref-fn">${esc(fn ? fnName(fn) : '')}</span></div>`;
    })
    .join('');
  return `<h3>${esc(tn('reference', 'Used {count} time in this program', 'Used {count} times in this program', total))}</h3><div class="reflist" style="max-height:360px">${rows}</div>${total > found.length ? `<p class="hint">${esc(tn('reference', 'The first {count} are listed.', 'The first {count} are listed.', found.length))}</p>` : ''}`;
}

function wordsPage(): string {
  const byCategory = new Map<string, Word[]>();
  const all = catalogue().words();
  for (const w of all) {
    const list = byCategory.get(w.category) ?? [];
    list.push(w);
    byCategory.set(w.category, list);
  }
  const fresh = all.filter((w) => w.status === 'new').length;
  let html = `<h2>${esc(t('reference', 'HLA64 vocabulary'))}</h2>
    <p class="lede">${esc(t('reference', 'HLA64 is an assembler with sugar: processor instructions as they are, plus words for what is obvious — assignments, expressions, memory access, if and goto, calls. The HLA64 view of the listing writes each instruction with these words where one fits and leaves it as an instruction where none does. Words marked new are additions made for reading disassembled code; they are not in the HLA64 translator yet.'))}</p>
    <div class="tags"><span class="tag tag--hla">${esc(tn('reference', '{count} HLA64 word', '{count} HLA64 words', all.length - fresh))}</span><span class="tag tag--new">${esc(tn('reference', '{count} new word', '{count} new words', fresh))}</span></div>`;
  for (const [category, words] of byCategory) {
    html += `<h3>${esc(category)}</h3><div class="words">${words
      .map(
        (w) =>
          `<div class="word-card"><div class="word-syntax">${esc(w.syntax)} ${w.status === 'new' ? `<span class="tag tag--new">${esc(t('reference', 'new'))}</span>` : '<span class="tag tag--hla">HLA64</span>'}</div><p class="word-desc">${esc(w.description)}</p><pre>${esc(catalogue().wordExample(w))}</pre>${catalogue().wordInstructions(w).length ? `<div class="word-for">${esc(t('reference', 'for'))} ${catalogue().wordInstructions(w).map((m) => `<a href="#" data-ref="${esc(catalogKey(m))}">${esc(m)}</a>`).join(', ')}</div>` : ''}</div>`,
      )
      .join('')}</div>`;
  }
  return html;
}

/** Builds the reference again in the interface language, on the same page. */
export function relocalizeReference(): void {
  const page = current;
  initReference(goTo);
  show(page);
}
