/**
 * The pieces the details panel and the pages are built of, the same for
 * every architecture: cards, key–value lists, tables, lists of places in the
 * code, the HLA64 words, and the cards an instruction, a function and a label
 * have whatever the architecture — the head of an instruction, its forms,
 * where it is called from, what it calls.
 *
 * The parts of the panel that differ (what an instruction's operands name,
 * how a method is declared) stay with each architecture (wasm.ts, cil.ts…).
 */

import { word, type Entry, type Form } from '../core/catalog';
import { IF, type Disassembly } from '../core/disassembly';
import { t, tn } from '../core/i18n';
import { categoryLabel, flagsLabel, groupLabel } from './labels';
import { fnName } from './state';
import { esc, hex } from './ui';

export const card = (title: string, body: string) => `<section class="card"><h3>${esc(title)}</h3>${body}</section>`;

/** A list of names and values; the values are HTML, a null row is left out. */
export const kv = (rows: (string[] | null)[]) => `<dl class="kv">${(rows.filter(Boolean) as string[][]).map(([k, v]) => `<dt>${esc(k!)}</dt><dd>${v}</dd>`).join('')}</dl>`;

/** A table of the pages; the body is the rows' HTML. */
export const table = (head: string[], body: string, id = '') => `<table class="table"${id ? ` id="${id}"` : ''}><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${body}</tbody></table>`;

export const hint = (text: string) => `<p class="hint">${esc(text)}</p>`;

/** How an offset into a function is written: `+1c` in native code and WebAssembly; .NET and Java pass their own (IL_001c, L28). */
export type OffsetText = (offset: number) => string;
const plusHex: OffsetText = (offset) => `+${offset.toString(16)}`;

/** `main +1c`: where an address in code is. */
export function where(p: Disassembly, addr: number, offsetText = plusHex): string {
  const fn = p.functions[p.functionOfIndex(p.indexOf(addr))];
  if (!fn) return hex(addr);
  const offset = addr - fn.addr;
  return `${esc(fnName(fn))}${offset ? ` ${offsetText(offset)}` : ''}`;
}

/** Places in the code, each a link to it. */
export function refList(p: Disassembly, addrs: number[], offsetText = plusHex, limit = 400): string {
  if (!addrs.length) return hint(t('inspector', 'Nothing in the code refers to it directly.'));
  const shown = addrs.slice(0, limit);
  const more = addrs.length > limit ? hint(tn('inspector', 'and {count} more', 'and {count} more', addrs.length - limit)) : '';
  return `<div class="reflist">${shown.map((addr) => `<div class="ref" data-goto="${addr}"><span>${addr.toString(16)}</span><span class="ref-fn">${where(p, addr, offsetText)}</span></div>`).join('')}</div>${more}`;
}

/** A function in a list: a link into the code, or to the import. */
export function calleeRef(fn: { addr: number; kind: string } & Parameters<typeof fnName>[0], left: string): string {
  const attr = fn.kind === 'import' ? `data-import="${fn.addr}"` : `data-goto="${fn.addr}"`;
  return `<div class="ref" ${attr}><span>${esc(left)}</span><span class="ref-fn">${esc(fnName(fn))}</span></div>`;
}

/** An HLA64 word, explained. */
export function wordCard(id: string): string {
  const w = word(id);
  if (!w) return '';
  const tag = w.status === 'new' ? `<span class="tag tag--new">${esc(t('inspector', 'new word'))}</span>` : `<span class="tag tag--hla">HLA64</span>`;
  return `<div class="word"><div class="word-syntax">${esc(w.syntax)} ${tag}</div><p class="word-desc">${esc(w.description)}</p></div>`;
}

/** The tooltip of an HLA64 word in a line (escaped for a data-tip attribute). */
export function wordTip(id: string): string {
  const w = word(id);
  if (!w) return '';
  return esc(`<b>${esc(w.syntax)}</b><span class="tt-sub">${esc(w.status === 'new' ? t('hla', 'New HLA64 word') : 'HLA64')} — ${esc(w.description)}</span>`);
}

/** The tooltip of a mnemonic: its summary, and what it does to the stack or, without a stack, its operation. */
export function mnemonicTip(m: string, entry: Entry | undefined): string {
  if (!entry) return esc(m);
  const sub = entry.stack ?? (entry.operation && entry.operation !== '—' ? entry.operation : '');
  return `<b>${esc(m)}</b> — ${esc(entry.summary)}${sub ? `<span class="tt-sub">${esc(sub)}</span>` : ''}`;
}

/** The head of an instruction's card: the mnemonic, the summary (or what stands for it without an entry), the entry's tags. */
export function insnHead(m: string, cls: string, entry: Entry | undefined, noEntry: string, extra: { tag?: string; button?: string } = {}): string {
  const title = `<div class="insn-title"><span class="insn-mn ${cls}">${esc(m)}</span><span class="insn-summary">${esc(entry?.summary ?? noEntry)}</span>${extra.button ?? ''}</div>`;
  if (!entry) return title;
  const tag = (text: string) => `<span class="tag">${esc(text)}</span>`;
  return `${title}<div class="tags">${tag(categoryLabel(entry.category))}${tag(groupLabel(entry.group))}${extra.tag ? tag(extra.tag) : ''}${entry.flags !== 'none' ? tag(flagsLabel(entry.flags)) : ''}</div>`;
}

/** The description of an instruction: its entry's, or what is said instead. */
export const insnDesc = (entry: Entry | undefined, instead = '') => (entry || instead ? `<p class="insn-desc">${esc(entry?.description ?? instead)}</p>` : '');

/** The HLA64 line of an instruction, a note on what it stands for, and its words explained. */
export const hlaCard = (lineHtml: string, note: string, words: string[]) => card(t('inspector', 'In HLA64'), `<div class="insn-text">${lineHtml}</div>${note ? hint(note) : ''}${words.map(wordCard).join('')}`);

/** Where a line that joins several instructions comes from. */
export const joinedNote = (count: number) => (count > 1 ? tn('inspector', 'This line stands for {count} instruction.', 'This line stands for {count} instructions.', count) : '');

/** The labels a branch goes to (instruction indices). */
export function goesToCard(p: Disassembly, targets: number[]): string {
  if (!targets.length) return '';
  const refs = targets.slice(0, 200).map((target) => {
    const addr = p.addrOf(target);
    return `<div class="ref" data-goto="${addr}"><span>${addr.toString(16)}</span><span class="ref-fn">${p.labelName(addr)}</span></div>`;
  });
  return card(t('inspector', 'Goes to'), `<div class="reflist">${refs.join('')}</div>`);
}

/** The forms of an instruction with links to their pages, and how often the program uses it. */
export function formsCard(forms: Form[], link: (form: Form) => { url: string; label: string }, ref: string, used: number, limit = 8): string {
  const html = forms
    .slice(0, limit)
    .map((form) => {
      const { url, label } = link(form);
      const isa = form.isa ? ` <span class="hint">${esc(form.isa.join(', '))}</span>` : '';
      const alias = form.aliasOf ? ` <span class="hint">${esc(t('inspector', 'alias of {name}', { name: form.aliasOf }))}</span>` : '';
      const a = url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>` : '';
      return `<div class="form-head">${esc(form.heading)}${isa}${alias}${a}</div>${form.syntax.slice(0, 4).map((s) => `<div class="syntax">${esc(s)}</div>`).join('')}`;
    })
    .join('');
  const usage = `<p class="hint"><a href="#" data-ref="${esc(ref)}">${esc(t('inspector', 'Open in the reference'))}</a> · ${esc(tn('inspector', 'used {count} time in this program', 'used {count} times in this program', used))}</p>`;
  return card(t('inspector', 'Forms and syntax'), html + usage);
}

export const calledFromCard = (p: Disassembly, callers: number[], offsetText = plusHex) => card(tn('inspector', 'Called from {count} place', 'Called from {count} places', callers.length), refList(p, callers, offsetText));

/** What a function calls: the rows (calleeRef and the like), and a note on the calls that are not direct. */
export const callsCard = (count: number, rows: string[], note = '') =>
  card(tn('inspector', 'Calls {count} function', 'Calls {count} functions', count), (rows.length ? `<div class="reflist">${rows.join('')}</div>` : hint(t('inspector', 'No direct calls.'))) + (note ? hint(note) : ''));

/** The strings a function uses, by address, each a link to it unless `linked` is false; the address is shown less `base` (Java's strings are numbered from one). */
export function stringsCard(strings: Map<number, string>, { linked = true, base = 0 } = {}): string {
  if (!strings.size) return '';
  const rows = [...strings].map(([addr, text]) => `<div class="ref"${linked ? ` data-mem="${addr}"` : ''}><span>${(addr - base).toString(16)}</span><span class="t-string">${esc(JSON.stringify(text.length > 70 ? `${text.slice(0, 70)}…` : text))}</span></div>`);
  return card(tn('inspector', 'Uses {count} string', 'Uses {count} strings', strings.size), `<div class="reflist">${rows.join('')}</div>`);
}

/** The branches of a label's function that go to it (instruction index → their addresses). */
export function branchesTo(p: Disassembly, index: number): number[] {
  const fn = p.functions[p.functionOfIndex(index)];
  const from: number[] = [];
  if (fn) for (let i = fn.first; i < fn.first + fn.count; i++) if (p.flags[i]! & IF.BRANCH && p.branchTargets(i).includes(index)) from.push(p.addrOf(i));
  return from;
}

/** A label: what it is (HTML), and the branches that reach it. */
export const labelInfoCard = (p: Disassembly, addr: number, what: string, from: number[], offsetText = plusHex) =>
  card(p.labelName(addr), `${what}<h3 style="margin-top:12px">${esc(tn('inspector', 'Reached from {count} branch', 'Reached from {count} branches', from.length))}</h3>${refList(p, from, offsetText)}`);
