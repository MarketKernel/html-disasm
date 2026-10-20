/**
 * The page's parts for 32-bit Arm code: the rows of the listing, the details
 * panel and where Enter leads. A32 and T32 instructions differ in size and
 * can be conditional through an IT block; literal pools and switch tables sit
 * among them as `.word`, `.short` or `.byte`. HLA64 has no 32-bit Arm target,
 * so the listing shows assembly only.
 */

import { F } from '../core/arm64/types';
import { arm32Unconditional, conditions } from '../core/catalog';
import { KIND, type Arm32Program } from '../core/arm32/program';
import { formatInsn, formatOp, type Insn, type Op } from '../core/arm32/types';
import { t, tn } from '../core/i18n';
import { sectionOf, valueAt } from '../core/image';
import { IF } from '../core/disassembly';
import { ROW, type Rows } from '../core/rows';
import { branchesTo, calledFromCard, callsCard, card, formsCard, insnDesc, insnHead, kv, labelInfoCard, mnemonicTip, refList, stringsCard, where } from './cards';
import { kindLabel } from './render';
import { catalogue, fnName, type Selection } from './state';
import { addrCell, clip, esc, hex } from './ui';

const COMPARES = /^(cmp|cmn|tst|teq|vcmp|vcmpe)/;

export function arm32Class(insn: Insn): string {
  if (insn.f & F.UNKNOWN) return 'k-unknown';
  if (insn.m.startsWith('.')) return 'k-data';
  if (insn.f & F.CALL) return 'k-call';
  if (insn.f & (F.BRANCH | F.TRAP)) return 'k-branch';
  if (insn.f & (F.LOAD | F.STORE)) return 'k-mem';
  if (COMPARES.test(insn.m)) return 'k-cmp';
  const entry = catalogue().lookup(insn.m);
  if (!entry) return '';
  if (entry.group === 'simd' || entry.group === 'fp') return 'k-simd';
  if (entry.group === 'system' || entry.category === 'hint' || entry.category === 'barrier') return 'k-sys';
  return '';
}

/** A code address by name: a function (as the settings name it) or a label. */
function nameOf(p: Arm32Program, addr: number): string | undefined {
  const fn = p.functionAt(addr);
  if (fn) return fnName(fn);
  return p.target(addr)?.name;
}

const OPERAND_TOKENS = /(#-?0x[0-9a-f]+|#-?\d+(?:\.\d+)?(?:e[+-]\d+)?)|(\b(?:r\d{1,2}|sp|lr|pc|[sdq]\d{1,2})\b)|(\b(?:lsl|lsr|asr|ror|rrx)\b)/g;

function opHtml(p: Arm32Program, op: Op): string {
  switch (op.k) {
    case 'reg':
      return `<span class="t-reg">${esc(formatOp(op))}</span>`;
    case 'imm':
      return `<span class="t-imm">${esc(op.t)}</span>`;
    case 'label': {
      const name = nameOf(p, op.addr);
      if (name) return `<span class="t-name" data-addr="${op.addr}" data-tip="${esc(esc(hex(op.addr)))}">${esc(name)}</span>`;
      return p.indexOf(op.addr) >= 0 ? `<span class="t-name" data-addr="${op.addr}">${hex(op.addr)}</span>` : `<span class="t-imm">${hex(op.addr)}</span>`;
    }
    case 'shift':
      return `<span class="t-op">${esc(op.t)}</span>`;
    default:
      return esc(op.t).replace(OPERAND_TOKENS, (_, num?: string, reg?: string, sh?: string) =>
        num ? `<span class="t-imm">${num}</span>` : reg ? `<span class="t-reg">${reg}</span>` : `<span class="t-op">${sh}</span>`,
      );
  }
}

export function arm32AsmHtml(p: Arm32Program, insn: Insn): string {
  const cls = arm32Class(insn);
  const ops = insn.ops.map((op) => opHtml(p, op)).join('<span class="t-op">, </span>');
  return `<span class="r-mn ${cls}" data-mn="${esc(insn.m)}" data-tip="${esc(mnemonicTip(insn.m, catalogue().lookup(insn.m)))}">${esc(insn.m)}</span> <span class="r-ops">${ops}</span>`;
}


/** What an address holds, for a comment: a string, a function, a symbol, or the section it is in. */
function addressText(p: Arm32Program, addr: number): string {
  const data = p.dataAt(addr);
  if (data?.kind === 'string') return `<span class="t-string" data-addr="${addr}">${esc(JSON.stringify(clip(data.text)))}</span>`;
  const name = nameOf(p, addr);
  if (name) return `<span class="t-name" data-addr="${addr}">${esc(name)}</span>`;
  if (data?.kind === 'symbol') return `<span class="t-name" data-mem="${addr}">${esc(data.name)}</span>`;
  const section = sectionOf(p.image, addr);
  // A slot the loader fills with an address (a table of pointers, a vtable): what it points at.
  const pointer = p.image.elf?.relative.get(addr);
  const pointed = pointer !== undefined && pointer !== addr ? pointerText(p, pointer) : '';
  return `<span data-mem="${addr}">${hex(addr)}</span>${section ? ` <span class="t-op">${esc(section.name)}+${(addr - section.addr).toString(16)}</span>` : ''}${pointed ? ` → ${pointed}` : ''}`;
}

/** The target of a pointer in data, named when it is a string or a function. */
function pointerText(p: Arm32Program, addr: number): string {
  // A pointer to Thumb code has bit 0 set; one to data is exact.
  const target = p.indexOf(addr & ~1) >= 0 ? addr & ~1 : addr;
  const data = p.dataAt(target);
  if (data?.kind === 'string') return `<span class="t-string" data-addr="${target}">${esc(JSON.stringify(clip(data.text)))}</span>`;
  const name = nameOf(p, target);
  if (name) return `<span class="t-name" data-addr="${target}">${esc(name)}</span>`;
  return data?.kind === 'symbol' ? `<span class="t-name" data-mem="${target}">${esc(data.name)}</span>` : '';
}

/** The comment of a row: the address an instruction makes or reads, a literal's value, a switch. */
function comment(p: Arm32Program, index: number, insn: Insn): string {
  const parts: string[] = [];
  const addr = p.addressAt.get(index);
  if (insn.f & F.LOAD && insn.target !== undefined && !(insn.f & F.BRANCH) && addr === undefined) {
    const value = insn.bytes === 4 || insn.bytes === undefined ? valueAt(p.image, insn.target, 4) : undefined;
    if (value !== undefined) parts.push(`<span class="t-imm">=${hex(value)}</span>`);
  }
  if (addr !== undefined) parts.push(addressText(p, addr));
  // A call through a register loaded from an import's slot names the import.
  const slot = p.slotCalls.get(index);
  if (slot !== undefined) parts.push(`<span class="t-name" data-mem="${slot}">${esc(p.image.demangle(p.importSlots.get(slot) ?? '').short)}</span>`);
  const table = p.tables.get(index);
  if (table) parts.push(esc(tn('listing', 'switch: {count} case', 'switch: {count} cases', table.length)));
  return parts.length ? `<span class="r-comment">; ${parts.join(' ')}</span>` : '';
}

function bytesOf(p: Arm32Program, index: number): string {
  const word = p.words[index]!;
  const hex2 = (v: number, digits: number) => v.toString(16).padStart(digits, '0');
  switch (p.kinds[index]) {
    case KIND.A32:
      return hex2(word >>> 0, 8);
    case KIND.T16:
      return hex2(word, 4);
    case KIND.T32:
      return `${hex2(word >>> 16, 4)} ${hex2(word & 0xffff, 4)}`;
    case KIND.WORD:
      return [word & 0xff, (word >>> 8) & 0xff, (word >>> 16) & 0xff, word >>> 24].map((b) => hex2(b, 2)).join(' ');
    case KIND.SHORT:
      return [word & 0xff, word >>> 8].map((b) => hex2(b, 2)).join(' ');
  }
  return hex2(word, 2);
}


function setOf(p: Arm32Program, index: number): string {
  return p.isThumb(index) ? 'T32' : p.isData(index) ? t('listing', 'data') : 'A32';
}

function fnMeta(p: Arm32Program, fnIndex: number): string {
  const fn = p.functions[fnIndex]!;
  const callers = p.callers.get(fn.addr)?.length ?? 0;
  const bytes = fn.count ? p.addrOf(fn.first + fn.count - 1) + p.sizeOf(fn.first + fn.count - 1) - fn.addr : 0;
  return [hex(fn.addr), setOf(p, fn.first), tn('listing', '{count} instruction', '{count} instructions', fn.count), tn('inspector', '{count} byte', '{count} bytes', bytes), fn.kind === 'anonymous' ? '' : kindLabel(fn.kind), callers ? tn('listing', '{count} caller', '{count} callers', callers) : '']
    .filter(Boolean)
    .join(' · ');
}

export function arm32RowHtml(p: Arm32Program, rows: Rows, r: number, selected: boolean, showBytes: boolean): string {
  const kind = rows.kind[r]!;
  const value = rows.value[r]!;
  const sel = selected ? ' is-selected' : '';
  switch (kind) {
    case ROW.SECTION: {
      const range = p.ranges[value]!;
      return `<div class="row section" data-row="${r}">; ${esc(range.section.label)} — ${esc(tn('listing', '{count} instruction', '{count} instructions', range.count))}</div>`;
    }
    case ROW.GAP:
      return `<div class="row gap" data-row="${r}"></div>`;
    case ROW.FN_HEADER: {
      const fn = p.functions[value]!;
      return `<div class="row fn${sel}" data-row="${r}"><span class="fn-title" title="${esc(fn.full)}">${esc(fnName(fn))}</span><span class="fn-meta">${esc(fnMeta(p, value))}</span></div>`;
    }
    case ROW.FN_END:
      return `<div class="row fn-end" data-row="${r}">}</div>`;
    case ROW.LABEL:
      return `<div class="row label${sel}" data-row="${r}">${addrCell(p.addrOf(value))}${p.labelName(p.addrOf(value))}:</div>`;
  }
  const insn = p.insn(value);
  const bytes = showBytes ? `<span class="r-bytes">${bytesOf(p, value)}</span>` : '';
  return `<div class="row${sel}" data-row="${r}">${addrCell(p.addrOf(value))}${bytes}<span class="r-code">${arm32AsmHtml(p, insn)}</span>${comment(p, value, insn)}</div>`;
}

/* ------------------------------------------------------------------ *
 * Details panel
 * ------------------------------------------------------------------ */

function bitsGrid(word: number, width: number): string {
  let cells = '';
  for (let b = width - 1; b >= 0; b--) {
    const one = (word >>> b) & 1;
    cells += `<span class="${one ? 'one' : ''}" title="bit ${b}">${one}</span>`;
  }
  const marks = width === 16 ? '<span>15</span><span>8</span><span>0</span>' : '<span>31</span><span>24</span><span>16</span><span>8</span><span>0</span>';
  return `<div class="bits${width === 16 ? ' bits--16' : ''}">${cells}</div><div class="bits-index">${marks}</div>`;
}

function encodingText(p: Arm32Program, index: number): string {
  switch (p.kinds[index]) {
    case KIND.T16:
      return t('inspector', 'T32 (Thumb), 16 bits');
    case KIND.T32:
      return t('inspector', 'T32 (Thumb-2), 32 bits');
    case KIND.A32:
      return t('inspector', 'A32 (Arm), 32 bits');
  }
  return t('inspector', 'data among the instructions');
}

function instructionCard(p: Arm32Program, index: number): string {
  const insn = p.insn(index);
  const addr = p.addrOf(index);
  const data = p.isData(index);
  const entry = data ? undefined : catalogue().lookup(insn.m);
  const cond = insn.cond;
  const condition = cond ? conditions()[cond] : undefined;
  const head = insnHead(insn.m, arm32Class(insn), entry, data ? t('inspector', 'Data in the code') : insn.f & F.UNKNOWN ? t('inspector', 'Not an instruction the decoder knows') : '', { tag: setOf(p, index) });
  const desc = insnDesc(
    entry,
    data
      ? p.mapped
        ? t('inspector', 'The library marks these bytes as data: a literal pool, a switch table or padding between functions.')
        : t('inspector', 'Bytes the code reads as data — a literal pool or a switch table — rather than instructions.')
      : t('inspector', 'The bytes do not decode to an instruction the decoder knows: they may be data in the code section, padding, or code of the other instruction set.'),
  );
  const width = p.kinds[index] === KIND.T16 || p.kinds[index] === KIND.SHORT || p.kinds[index] === KIND.BYTE ? 16 : 32;
  const word = p.words[index]!;
  const rows = kv([
    entry?.operation && entry.operation !== '—' ? [t('inspector', 'Does'), esc(entry.operation)] : null,
    condition ? [t('inspector', 'Condition'), `${esc(cond!)} — ${esc(condition.name)} (${esc(condition.flags)})${p.its[index]! >= 0 ? ` · ${esc(t('inspector', 'from the IT block before it'))}` : ''}`] : null,
    [t('inspector', 'Instruction set'), esc(encodingText(p, index))],
    [t('inspector', 'Address'), hex(addr)],
    [t('inspector', 'In'), where(p, addr)],
    [t('inspector', 'Encoding'), `<span class="mono">${esc(bytesOf(p, index))}</span>`],
    insn.bytes && !data ? [t('inspector', 'Memory'), tn('inspector', '{count} byte', '{count} bytes', insn.bytes)] : null,
  ]);
  let html = `<section class="card">${head}<div class="insn-text">${esc(formatInsn(insn))}</div>${desc}${rows}${bitsGrid(word, width)}</section>`;

  if (insn.it) {
    const names = insn.it.map((c) => conditions()[['eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al'][c] ?? 'al']?.name ?? '');
    const list = insn.it.map((_, k) => `<div class="ref"${index + 1 + k < p.totalInstructions ? ` data-goto="${p.addrOf(index + 1 + k)}"` : ''}><span>${k + 1}</span><span class="ref-fn">${esc(names[k]!)}</span></div>`).join('');
    html += card(tn('inspector', 'Makes {count} instruction conditional', 'Makes {count} instructions conditional', insn.it.length), `<div class="reflist">${list}</div>`);
  }
  const table = p.tables.get(index);
  if (table) {
    const list = table.map((target, k) => `<div class="ref" data-goto="${target}"><span>${k}</span><span class="ref-fn">${esc(nameOf(p, target) ?? hex(target))}</span></div>`).join('');
    html += card(tn('inspector', 'Switch with {count} case', 'Switch with {count} cases', table.length), `<div class="reflist">${list}</div>`);
  } else if (insn.target !== undefined && insn.f & (F.BRANCH | F.CALL) && !(insn.f & F.INDIRECT) && p.indexOf(insn.target) >= 0) {
    const mode = insn.thumb === undefined ? '' : ` <span class="hint">${insn.thumb ? 'T32' : 'A32'}</span>`;
    html += card(insn.f & F.CALL ? t('inspector', 'Calls') : t('inspector', 'Goes to'), `<div class="ref" data-goto="${insn.target}"><span>${insn.target.toString(16)}</span><span class="ref-fn">${esc(nameOf(p, insn.target) ?? hex(insn.target))}${mode}</span></div>`);
  }
  const dataAddr = p.addressAt.get(index);
  if (dataAddr !== undefined) html += dataCard(p, dataAddr);

  if (entry) {
    const forms = [...entry.forms].sort((a, b) => Number(!!a.aliasOf) - Number(!!b.aliasOf));
    const counted = arm32Unconditional(insn.m.replace(/\.[wn]$/, ''));
    const used = p.counts.filter((c) => arm32Unconditional(c.mnemonic) === counted).reduce((n, c) => n + c.count, 0);
    html += formsCard(forms, (form) => ({ url: catalogue().docUrl(form), label: 'Arm ↗' }), catalogue().key(insn.m), used);
  }
  return html;
}

function dataCard(p: Arm32Program, addr: number): string {
  const data = p.dataAt(addr);
  const refs = p.dataRefs.get(addr) ?? [];
  let body = '';
  if (data?.kind === 'string') body += `<div class="pre">${esc(data.text)}</div>`;
  else if (data?.kind === 'symbol') body += `<p class="mono">${esc(data.name)}</p>`;
  else {
    const fn = p.functionAt(addr);
    if (fn) body += `<p class="mono"><a href="#" data-goto="${addr}">${esc(fnName(fn))}</a></p>`;
  }
  body += kv([
    [t('inspector', 'Address'), hex(addr)],
    [t('inspector', 'Section'), esc(sectionOf(p.image, addr)?.label ?? '—')],
  ]);
  body += `<h3 style="margin-top:12px">${esc(tn('inspector', '{count} reference', '{count} references', refs.length))}</h3>${refList(p, refs)}`;
  return card(data?.kind === 'string' ? t('inspector', 'String') : t('inspector', 'Data'), body);
}

function fnCard(p: Arm32Program, index: number): string {
  const fn = p.functions[index]!;
  const callers = p.callers.get(fn.addr) ?? [];
  const calls = new Map<number, number>();
  const strings = new Map<number, string>();
  const limit = Math.min(fn.count, 20000);
  for (let i = fn.first; i < fn.first + limit; i++) {
    if (p.flags[i]! & IF.CALL) {
      const insn = p.insn(i);
      if (insn.target !== undefined) calls.set(insn.target, (calls.get(insn.target) ?? 0) + 1);
    }
    const addr = p.addressAt.get(i);
    const data = addr !== undefined ? p.dataAt(addr) : undefined;
    if (addr !== undefined && data?.kind === 'string') strings.set(addr, data.text);
  }
  const last = fn.first + fn.count - 1;
  const bytes = fn.count ? p.addrOf(last) + p.sizeOf(last) - fn.addr : 0;
  let html = card(
    t('inspector', 'Function'),
    kv([
      [t('inspector', 'Name'), esc(fnName(fn))],
      fn.full !== fn.name ? [t('inspector', 'Full name'), esc(fn.full)] : null,
      fn.raw ? [t('inspector', 'Symbol'), esc(fn.raw)] : null,
      [t('inspector', 'Kind'), esc(kindLabel(fn.kind)) + (fn.language && fn.language !== 'other' ? ` · ${esc(fn.language)}` : '')],
      [t('inspector', 'Instruction set'), esc(fn.count ? encodingText(p, fn.first) : '—')],
      [t('inspector', 'Address'), `${hex(fn.addr)} – ${hex(fn.addr + bytes)}`],
      [t('inspector', 'Size'), `${tn('inspector', '{count} instruction', '{count} instructions', fn.count)} · ${tn('inspector', '{count} byte', '{count} bytes', bytes)}`],
    ]),
  );
  html += calledFromCard(p, callers);
  const callList = [...calls].sort((a, b) => b[1] - a[1]);
  html += callsCard(callList.length, callList.map(([addr, n]) => `<div class="ref" data-goto="${addr}"><span>${n}×</span><span class="ref-fn">${esc(nameOf(p, addr) ?? hex(addr))}</span></div>`));
  html += stringsCard(strings);
  return html;
}

function labelCard(p: Arm32Program, index: number): string {
  return labelInfoCard(p, p.addrOf(index), `<p class="insn-desc">${esc(t('inspector', 'A place branches go to.'))}</p>`, branchesTo(p, index)) + instructionCard(p, index);
}

function importCard(p: Arm32Program, name: string, addr?: number): string {
  const fn = addr !== undefined ? p.functionAt(addr) : undefined;
  const raw = fn?.raw ?? name;
  const imp = p.image.imports.find((i) => i.name === raw);
  const callers = addr !== undefined ? p.callers.get(addr) ?? [] : [];
  return (
    card(
      t('inspector', 'Imported function'),
      kv([
        [t('inspector', 'Name'), esc(p.image.demangle(raw).full)],
        raw !== p.image.demangle(raw).full ? [t('inspector', 'Symbol'), esc(raw)] : null,
        imp?.library ? [t('inspector', 'Library'), esc(imp.library)] : null,
        imp?.version ? [t('inspector', 'Version'), esc(imp.version)] : null,
        fn ? [t('inspector', 'Stub'), `<a href="#" data-goto="${fn.addr}">${hex(fn.addr)}</a>`] : null,
      ]),
    ) + calledFromCard(p, callers)
  );
}

/** The details panel for whatever is selected in 32-bit Arm code. */
export function arm32Inspector(p: Arm32Program, sel: NonNullable<Selection>): string {
  switch (sel.kind) {
    case 'insn':
      return instructionCard(p, sel.index);
    case 'fn':
      return fnCard(p, sel.fn);
    case 'label':
      return labelCard(p, sel.index);
    case 'string':
      return dataCard(p, sel.addr);
    case 'import':
      return importCard(p, sel.name, sel.addr);
  }
}

/** Where Enter goes from an instruction: a branch or call target, or the data it makes an address of. */
export function arm32Follow(p: Arm32Program, index: number): { code?: number; mem?: number } {
  const [target] = p.branchTargets(index);
  if (target !== undefined) return { code: p.addrOf(target) };
  const insn = p.insn(index);
  if (insn.target !== undefined && insn.f & F.CALL) return { code: insn.target };
  const addr = p.addressAt.get(index);
  if (addr !== undefined) return p.indexOf(addr) >= 0 ? { code: addr } : { mem: addr };
  return {};
}
