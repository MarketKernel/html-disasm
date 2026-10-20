/**
 * The details panel: everything about what is selected. For an instruction
 * that is the catalogue's explanation of it, its HLA64 line and the words
 * that line uses, its encoding bit by bit, the forms and syntax with links to
 * Arm's pages, and where it leads. For a function: its names, size, callers,
 * the functions it calls and the strings it uses. For a label, a string or an
 * import: who refers to it.
 */

import { F } from '../core/arm64/types';
import { catalogKey, conditionOf, conditions, docUrl, lookup } from '../core/catalog';
import { calledFromCard, callsCard, card, formsCard, hlaCard, insnDesc, insnHead, kv, labelInfoCard, refList, stringsCard, where } from './cards';
import { pairedAddress, rawInstruction } from '../core/hla';
import { t, tn } from '../core/i18n';
import { sectionOf } from '../core/image';
import { IF } from '../core/program';
import { hlaHtml, hlaLine, kindLabel, mnemonicClass } from './render';
import { armProgram, context, fnName, on, select, state } from './state';
import { canPatch, isPatched, openEditor } from './patch';
import { viewOf } from './views';
import { $, esc, hex } from './ui';

let goTo: (addr: number) => void = () => {};

/** A name in a line: code goes to the listing; an imported function is selected. */
function followAddr(addr: number): void {
  const p = state.program;
  if (!p) return;
  if (p.indexOf(addr) >= 0) goTo(addr);
  else {
    const member = viewOf(p).importAt(addr);
    if (member) select({ kind: 'import', name: member.raw ?? member.name, addr });
  }
}
let openReference: (mnemonic: string) => void = () => {};

export function initInspector(navigate: (addr: number) => void, reference: (mnemonic: string) => void): void {
  goTo = navigate;
  openReference = reference;
  const panel = $('inspector');
  panel.addEventListener('click', (event) => {
    const target = event.target as HTMLElement;
    const go = target.closest<HTMLElement>('[data-goto]');
    if (go) goTo(Number(go.dataset.goto));
    const editBtn = target.closest<HTMLElement>('[data-edit]');
    if (editBtn) {
      openEditor(Number(editBtn.dataset.edit));
      return;
    }
    const ref = target.closest<HTMLElement>('[data-ref]');
    if (ref) openReference(ref.dataset.ref!);
    const mem = target.closest<HTMLElement>('[data-mem]');
    if (mem) select({ kind: 'string', addr: Number(mem.dataset.mem) });
    const imp = target.closest<HTMLElement>('[data-import]');
    if (imp) select({ kind: 'import', name: '', addr: Number(imp.dataset.import) });
    const addr = target.closest<HTMLElement>('[data-addr]');
    if (addr && !go) followAddr(Number(addr.dataset.addr));
  });
  on('select', render);
  on('settings', render);
  on('mode', render);
  render();
}

function render(): void {
  const panel = $('inspector');
  if (!state.program) {
    panel.innerHTML = '';
    return;
  }
  const sel = state.selection;
  if (!sel) {
    panel.innerHTML = `<div class="inspector-empty">${esc(t('inspector', 'Select an instruction to see what it does.'))}</div>`;
    return;
  }
  const own = viewOf(state.program).inspector;
  if (own) {
    panel.innerHTML = own(sel);
    return;
  }
  switch (sel.kind) {
    case 'insn':
      panel.innerHTML = instruction(sel.index);
      break;
    case 'fn':
      panel.innerHTML = fnCard(sel.fn);
      break;
    case 'label':
      panel.innerHTML = labelCard(sel.index);
      break;
    case 'string':
      panel.innerHTML = stringCard(sel.addr);
      break;
    case 'import':
      panel.innerHTML = importCard(sel.name, sel.addr);
      break;
  }
}

function bitsGrid(word: number): string {
  let cells = '';
  for (let b = 31; b >= 0; b--) {
    const one = (word >>> b) & 1;
    cells += `<span class="${one ? 'one' : ''}" title="bit ${b}">${one}</span>`;
  }
  return `<div class="bits">${cells}</div><div class="bits-index"><span>31</span><span>24</span><span>16</span><span>8</span><span>0</span></div>`;
}

function instruction(index: number): string {
  const p = armProgram();
  const insn = p.insn(index);
  const addr = p.addrOf(index);
  const word = p.words[index]!;
  const entry = lookup(insn.m);
  const ctx = context();
  const asm = rawInstruction(word, addr, ctx);
  const cond = insn.cond ?? conditionOf(insn.m);
  const condition = cond ? conditions()[cond] : undefined;

  let html = '';
  const edit = canPatch() ? `<button class="button button--small insn-edit" type="button" data-edit="${index}">${esc(isPatched(index) ? t('inspector', 'Changed — edit') : t('inspector', 'Change…'))}</button>` : '';
  const head = insnHead(insn.m, mnemonicClass(insn), entry, insn.f & F.UNKNOWN ? t('inspector', 'Not an instruction the decoder knows') : '', { button: edit });
  const text = `<div class="insn-text">${esc(asm)}</div>`;
  const desc = insnDesc(entry, t('inspector', 'The word does not decode to an instruction the decoder knows: it may be data in the code section, padding, or an instruction from an extension (SVE, SME) that is not decoded.'));
  const rows = kv([
    entry?.operation && entry.operation !== '—' ? [t('inspector', 'Does'), esc(entry.operation)] : null,
    condition ? [t('inspector', 'Condition'), `${esc(cond!)} — ${esc(condition.name)} (${esc(condition.flags)})`] : null,
    [t('inspector', 'Address'), `${hex(addr)}`],
    [t('inspector', 'In'), where(p, addr)],
    [t('inspector', 'Encoding'), `0x${word.toString(16).padStart(8, '0')}`],
    insn.size ? [t('inspector', 'Memory'), tn('inspector', '{count} byte', '{count} bytes', insn.size) + (insn.signed ? `, ${t('inspector', 'sign-extended')}` : '')] : null,
  ]);
  html += `<section class="card">${head}${text}${desc}${rows}${bitsGrid(word)}</section>`;

  // HLA64
  const { line, link } = hlaLine(p, index);
  const fused = p.flags[index]! & IF.FUSE;
  const pairNote = fused && line.words[0] !== 'instruction' ? t('inspector', 'This line stands for this instruction and the next one.') : '';
  html += hlaCard(`${hlaHtml(line.text, link)}${line.comment ? ` <span class="t-comment">// ${esc(line.comment)}</span>` : ''}`, pairNote, line.words);

  // Where it leads
  const target = insn.target;
  let dataAddr: number | undefined;
  if (insn.m === 'adrp' && index + 1 < p.totalInstructions) dataAddr = pairedAddress(word, addr, p.words[index + 1]!, p.addrOf(index + 1));
  if (index > 0 && p.flags[index - 1]! & IF.FUSE) {
    const prev = p.insn(index - 1);
    if (prev.m === 'adrp') dataAddr = pairedAddress(p.words[index - 1]!, p.addrOf(index - 1), word, addr);
  }
  if (target !== undefined && insn.m !== 'adrp' && p.indexOf(target) >= 0) {
    const name = ctx.target(target);
    html += card(insn.f & F.CALL ? t('inspector', 'Calls') : t('inspector', 'Goes to'), `<div class="ref" data-goto="${target}"><span>${target.toString(16)}</span><span class="ref-fn">${esc(name?.name ?? hex(target))}</span></div>`);
  }
  if (dataAddr !== undefined) html += dataCard(dataAddr);

  // Forms and links
  if (entry) html += formsCard(entry.forms, (form) => ({ url: docUrl(form), label: 'Arm ↗' }), catalogKey(insn.m), countOf(insn.m));
  return html;
}

function countOf(mnemonic: string): number {
  return armProgram().counts.find((c) => c.mnemonic === mnemonic)?.count ?? 0;
}


function dataCard(addr: number): string {
  const p = armProgram();
  const data = p.dataAt(addr);
  const refs = p.dataRefs.get(addr) ?? [];
  let body = '';
  if (data?.kind === 'string') body += `<div class="pre">${esc(data.text)}</div>`;
  else if (data?.kind === 'symbol') body += `<p class="mono">${esc(data.name)}</p>`;
  body += kv([
    [t('inspector', 'Address'), hex(addr)],
    [t('inspector', 'Section'), esc(sectionName(addr))],
  ]);
  body += `<h3 style="margin-top:12px">${esc(tn('inspector', '{count} reference', '{count} references', refs.length))}</h3>${refList(p, refs)}`;
  return card(data?.kind === 'string' ? t('inspector', 'String') : t('inspector', 'Data'), body);
}

function sectionName(addr: number): string {
  return sectionOf(armProgram().image, addr)?.label ?? '—';
}

function fnCard(index: number): string {
  const p = armProgram();
  const fn = p.functions[index]!;
  const callers = p.callers.get(fn.addr) ?? [];
  const calls = new Map<number, number>();
  const strings = new Map<number, string>();
  const limit = Math.min(fn.count, 20000);
  for (let i = fn.first; i < fn.first + limit; i++) {
    const flags = p.flags[i]!;
    if (flags & IF.CALL) {
      const insn = p.insn(i);
      if (insn.target !== undefined) calls.set(insn.target, (calls.get(insn.target) ?? 0) + 1);
    }
    if (flags & IF.FUSE && i + 1 < p.totalInstructions) {
      const insn = p.insn(i);
      if (insn.m !== 'adrp') continue;
      const addr = pairedAddress(p.words[i]!, p.addrOf(i), p.words[i + 1]!, p.addrOf(i + 1));
      const data = addr !== undefined ? p.dataAt(addr) : undefined;
      if (addr !== undefined && data?.kind === 'string') strings.set(addr, data.text);
    }
  }
  const names = [
    [t('inspector', 'Name'), esc(fnName(fn))],
    fn.full !== fn.name ? [t('inspector', 'Full name'), esc(fn.full)] : null,
    fn.raw ? [t('inspector', 'Symbol'), esc(fn.raw)] : null,
    [t('inspector', 'Kind'), esc(kindLabel(fn.kind)) + (fn.language && fn.language !== 'other' ? ` · ${esc(fn.language)}` : '')],
    [t('inspector', 'Address'), `${hex(fn.addr)} – ${hex(fn.addr + fn.count * 4)}`],
    [t('inspector', 'Size'), `${tn('inspector', '{count} instruction', '{count} instructions', fn.count)} · ${tn('inspector', '{count} byte', '{count} bytes', fn.count * 4)}`],
  ].filter(Boolean) as string[][];
  let html = card(t('inspector', 'Function'), `<dl class="kv">${names.map(([k, v]) => `<dt>${esc(k!)}</dt><dd>${v}</dd>`).join('')}</dl>`);
  html += calledFromCard(p, callers);
  const callList = [...calls].sort((a, b) => b[1] - a[1]);
  html += callsCard(callList.length, callList.map(([addr, n]) => `<div class="ref" data-goto="${addr}"><span>${n}×</span><span class="ref-fn">${esc(context().target(addr)?.name ?? hex(addr))}</span></div>`));
  html += stringsCard(strings);
  return html;
}

function labelCard(index: number): string {
  const p = armProgram();
  const addr = p.addrOf(index);
  const fnIndex = p.functionOfIndex(index);
  const fn = p.functions[fnIndex];
  const from: number[] = [];
  if (fn) {
    for (let i = fn.first; i < fn.first + fn.count; i++) {
      if (!(p.flags[i]! & IF.BRANCH)) continue;
      if (p.insn(i).target === addr) from.push(p.addrOf(i));
    }
  }
  return labelInfoCard(p, addr, `<p class="insn-desc">${esc(t('inspector', 'A place branches go to.'))}</p>`, from) + instruction(index);
}

function stringCard(addr: number): string {
  return dataCard(addr);
}

function importCard(name: string, addr?: number): string {
  const p = armProgram();
  const imp = p.image.imports.find((i) => i.name === name);
  const fn = addr !== undefined ? p.functionAt(addr) : undefined;
  const callers = addr !== undefined ? p.callers.get(addr) ?? [] : [];
  const rows = kv([
    [t('inspector', 'Name'), esc(name.replace(/^_/, ''))],
    imp ? [t('inspector', 'Library'), esc(imp.library)] : null,
    fn ? [t('inspector', 'Stub'), hex(fn.addr)] : null,
  ]);
  return card(t('inspector', 'Imported function'), rows) + calledFromCard(p, callers);
}

export { hlaHtml };
