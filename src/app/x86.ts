/**
 * The page's parts for x86 code (x86-64 and i386): the rows of the listing,
 * in assembly and — for x86-64 — in HLA64, the details panel and where
 * Enter leads. Instructions are one to fifteen bytes; switch tables found
 * among them are data (`.long`); calls and jumps through an import's slot
 * name the import.
 */

import { F } from '../core/arm64/types';
import type { HlaLine } from '../core/hla';
import { liftX86, type X86LiftContext } from '../core/x86/hla';
import { IF } from '../core/disassembly';
import { n, t, tn } from '../core/i18n';
import { sectionOf } from '../core/image';
import { ROW, type Rows } from '../core/rows';
import { formatAddress } from '../core/x86/print';
import type { X86Insn, X86Program } from '../core/x86/program';
import { branchesTo, calledFromCard, callsCard, card, formsCard, hlaCard, insnDesc, insnHead, kv, labelInfoCard, mnemonicTip, refList, stringsCard, where } from './cards';
import { hlaHtml, kindLabel } from './render';
import { catalogue, fnName, importCallers, type Selection } from './state';
import { addrCell, clip, esc, hex } from './ui';

const COMPARES = /^(cmp|test|ucomis[sd]|vucomis[sd]|comis[sd]|vcomis[sd]|bt|ptest|vptest|ccmp|ctest)/;

export function x86Class(insn: X86Insn): string {
  if (insn.f & F.UNKNOWN) return 'k-unknown';
  if (insn.m.startsWith('.')) return 'k-data';
  if (insn.f & F.CALL) return 'k-call';
  if (insn.f & (F.BRANCH | F.TRAP)) return 'k-branch';
  if (COMPARES.test(insn.m) || /^(cmp|vcmp|vpcmp|vpcom)/.test(insn.m)) return 'k-cmp';
  const entry = catalogue().lookup(insn.m);
  if (entry?.group === 'simd' || entry?.group === 'x87') return 'k-simd';
  if (entry?.group === 'system') return 'k-sys';
  if (insn.f & (F.LOAD | F.STORE)) return 'k-mem';
  return '';
}

/** A code address by name: a function (as the settings name it) or a label. */
function nameOf(p: X86Program, addr: number): string | undefined {
  const fn = p.functionAt(addr);
  if (fn) return fnName(fn);
  return p.target(addr)?.name;
}

const OPERAND_TOKENS = /(\{[a-z0-9-]+(?:=[a-z,]*)?\})|(-?0x[0-9a-f]+|\b\d+\b)|(\b(?:[re]?[abcd]x|[abcd][lh]|[re]?(?:si|di|sp|bp|ip)|[sd]il|[sb]pl|r\d{1,2}[bwd]?|[xyz]mm\d{1,2}|k[0-7]|mm[0-7]|st(?:\(\d\))?|tmm\d|[cdefgs]s|[cd]r\d{1,2}|[re]iz)\b)|(\b(?:byte|word|dword|qword|tbyte|xmmword|ymmword|zmmword) ptr\b)/g;

/** The operands, coloured, with the branch target named and linked. */
function opsHtml(p: X86Program, insn: X86Insn): string {
  let text = insn.ops;
  let link = '';
  if (insn.target !== undefined && !(insn.f & F.INDIRECT)) {
    // The target is the last thing on the line: `call 0x401000`, `jne 0x10f8`.
    const shown = formatAddress(insn.target);
    if (text.endsWith(shown)) {
      text = text.slice(0, -shown.length);
      const name = nameOf(p, insn.target);
      link = name
        ? `<span class="t-name" data-addr="${insn.target}" data-tip="${esc(esc(hex(insn.target)))}">${esc(name)}</span>`
        : p.indexOf(insn.target) >= 0
          ? `<span class="t-name" data-addr="${insn.target}">${shown}</span>`
          : `<span class="t-imm">${shown}</span>`;
    }
  }
  const coloured = esc(text).replace(OPERAND_TOKENS, (match, brace?: string, num?: string, reg?: string, size?: string) =>
    brace ? `<span class="t-op">${brace}</span>` : num ? `<span class="t-imm">${num}</span>` : reg ? `<span class="t-reg">${reg}</span>` : size ? `<span class="t-op">${size}</span>` : match,
  );
  return coloured + link;
}

export function x86AsmHtml(p: X86Program, insn: X86Insn): string {
  const cls = x86Class(insn);
  const prefix = insn.prefix ? `<span class="t-op">${esc(insn.prefix)}</span> ` : '';
  return `${prefix}<span class="r-mn ${cls}" data-mn="${esc(insn.m)}" data-tip="${esc(mnemonicTip(insn.m, catalogue().lookup(insn.m)))}">${esc(insn.m)}</span> <span class="r-ops">${opsHtml(p, insn)}</span>`;
}


/** What an address holds, for a comment: a string, a function, an import, a symbol, or the section it is in. */
function addressText(p: X86Program, addr: number): string {
  const imported = p.importSlots.get(addr);
  if (imported) return `<span class="t-name" data-mem="${addr}">${esc(p.image.demangle(imported).short)}</span>`;
  const data = p.dataAt(addr);
  if (data?.kind === 'string') return `<span class="t-string" data-addr="${addr}">${data.objc ? '@' : ''}${esc(JSON.stringify(clip(data.text)))}</span>`;
  const name = nameOf(p, addr);
  if (name) return `<span class="t-name" data-addr="${addr}">${esc(name)}</span>`;
  if (data?.kind === 'symbol') return `<span class="t-name" data-mem="${addr}">${esc(data.name)}</span>`;
  const section = sectionOf(p.image, addr);
  return `<span data-mem="${addr}">${hex(addr)}</span>${section ? ` <span class="t-op">${esc(section.name)}+${(addr - section.addr).toString(16)}</span>` : ''}`;
}

/** The comment of a row: the address an instruction names, a switch. */
function comment(p: X86Program, index: number): string {
  const parts: string[] = [];
  const addr = p.addressAt.get(index);
  if (addr !== undefined) parts.push(addressText(p, addr));
  const code = p.codeAt.get(index);
  if (code !== undefined) parts.push(`<span class="t-name" data-addr="${code}">${esc(nameOf(p, code) ?? hex(code))}</span>`);
  const table = p.tables.get(index);
  if (table) parts.push(esc(tn('listing', 'switch: {count} case', 'switch: {count} cases', table.length)));
  return parts.length ? `<span class="r-comment">; ${parts.join(' ')}</span>` : '';
}

function bytesOf(p: X86Program, index: number): string {
  const range = p.rangeOfIndex(index)!;
  const at = range.section.offset + p.offs[index]!;
  const length = p.isData(index) ? p.sizeOf(index) : p.insn(index).length;
  return [...p.image.bytes.subarray(at, at + Math.min(length, 15))].map((b) => b.toString(16).padStart(2, '0')).join(' ');
}

/** The bytes column: seven bytes cover most instructions, a longer one ends in an ellipsis with the whole encoding in its tooltip (and the inspector). */
function bytesCell(p: X86Program, index: number): string {
  const full = bytesOf(p, index);
  if (full.length <= 20) return `<span class="r-bytes r-bytes--x86">${full}</span>`;
  return `<span class="r-bytes r-bytes--x86" title="${full}">${full.slice(0, 20)} …</span>`;
}


/** The lifting context, with functions named as the settings ask. */
function liftContext(p: X86Program): X86LiftContext {
  const base = p.context();
  return {
    ...base,
    target: (addr) => {
      const found = base.target(addr);
      if (found && found.kind !== 'label') {
        const fn = p.functionAt(addr);
        if (fn) return { ...found, name: fnName(fn) };
      }
      return found;
    },
  };
}

/** The HLA64 line of an instruction row: joined with the next one when the analysis marked the pair. */
export function x86HlaLine(p: X86Program, index: number, ctx = liftContext(p)): { line: HlaLine; insn: X86Insn; fused: boolean } {
  const insn = p.insn(index);
  const next = p.flags[index]! & IF.FUSE && index + 1 < p.totalInstructions ? p.insn(index + 1) : undefined;
  const line = liftX86(insn, ctx, next);
  return { line, insn, fused: line.fused };
}

/** An instruction row in HLA64: the line, or the instruction in colour when HLA64 keeps it as it is. */
function hlaRow(p: X86Program, index: number): string {
  const { line, insn } = x86HlaLine(p, index);
  if (line.words[0] === 'instruction') return x86AsmHtml(p, insn);
  return hlaHtml(line.text, insn.target ?? p.addressAt.get(index) ?? p.codeAt.get(index));
}

function fnMeta(p: X86Program, fnIndex: number): string {
  const fn = p.functions[fnIndex]!;
  const callers = p.callers.get(fn.addr)?.length ?? 0;
  const bytes = fnBytes(p, fnIndex);
  return [hex(fn.addr), tn('listing', '{count} instruction', '{count} instructions', fn.count), tn('inspector', '{count} byte', '{count} bytes', bytes), fn.kind === 'anonymous' ? '' : kindLabel(fn.kind), callers ? tn('listing', '{count} caller', '{count} callers', callers) : '']
    .filter(Boolean)
    .join(' · ');
}

function fnBytes(p: X86Program, fnIndex: number): number {
  const fn = p.functions[fnIndex]!;
  if (!fn.count) return 0;
  const last = fn.first + fn.count - 1;
  return p.addrOf(last) + p.sizeOf(last) - fn.addr;
}

export function x86RowHtml(p: X86Program, rows: Rows, r: number, selected: boolean, showBytes: boolean): string {
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
      if (rows.mode === 'hla') {
        const name = /^[A-Za-z_][A-Za-z0-9_]*$/.test(fnName(fn)) ? fnName(fn) : `\`${fnName(fn)}\``;
        return `<div class="row fn hla${sel}" data-row="${r}"><span class="r-code"><span class="t-kw">fn</span> <span class="t-name" data-addr="${fn.addr}">${esc(name)}</span>() {</span><span class="r-comment">// ${esc(fnMeta(p, value))}</span></div>`;
      }
      return `<div class="row fn${sel}" data-row="${r}"><span class="fn-title" title="${esc(fn.full)}">${esc(fnName(fn))}</span><span class="fn-meta">${esc(fnMeta(p, value))}</span></div>`;
    }
    case ROW.FN_END:
      return `<div class="row fn-end" data-row="${r}">}</div>`;
    case ROW.LABEL:
      return `<div class="row label${sel}" data-row="${r}">${rows.mode === 'hla' ? '' : addrCell(p.addrOf(value))}${p.labelName(p.addrOf(value))}:</div>`;
    case ROW.PAD: {
      const count = rows.span.get(r) ?? 1;
      const last = value + count - 1;
      const bytes = p.addrOf(last) + p.sizeOf(last) - p.addrOf(value);
      const insn = p.insn(value);
      return `<div class="row pad${sel}" data-row="${r}">${addrCell(p.addrOf(value))}${rows.mode === 'hla' ? '<span class="r-indent"></span>' : ''}<span class="r-code">${x86AsmHtml(p, insn)} <span class="t-op">× ${n(count)}</span></span><span class="r-comment">; ${esc(t('listing', 'padding'))}, ${esc(tn('inspector', '{count} byte', '{count} bytes', bytes))}</span></div>`;
    }
  }
  const bytes = showBytes ? bytesCell(p, value) : '';
  if (rows.mode === 'hla') return `<div class="row${sel}" data-row="${r}">${addrCell(p.addrOf(value))}${bytes}<span class="r-indent"></span><span class="r-code">${hlaRow(p, value)}</span></div>`;
  const insn = p.insn(value);
  return `<div class="row${sel}" data-row="${r}">${addrCell(p.addrOf(value))}${bytes}<span class="r-code">${x86AsmHtml(p, insn)}</span>${comment(p, value)}</div>`;
}

/* ------------------------------------------------------------------ *
 * Details panel
 * ------------------------------------------------------------------ */

function instructionCard(p: X86Program, index: number): string {
  const insn = p.insn(index);
  const addr = p.addrOf(index);
  const data = p.isData(index);
  const entry = data ? undefined : catalogue().lookup(insn.m);
  const head = insnHead(insn.m, x86Class(insn), entry, data ? t('inspector', 'Data in the code') : insn.f & F.UNKNOWN ? t('inspector', 'Not an instruction the decoder knows') : '');
  const desc = insnDesc(
    entry,
    data
      ? t('inspector', 'Bytes the code reads as data — a switch table — rather than instructions.')
      : insn.f & F.UNKNOWN
        ? t('inspector', 'The bytes do not decode to an instruction: they may be data in the code section or padding. Decoding goes on after the bytes LLVM would skip.')
        : '',
  );
  const text = [insn.prefix, insn.m, insn.ops].filter(Boolean).join(' ');
  const rows = kv([
    entry?.operation && entry.operation !== '—' ? [t('inspector', 'Does'), esc(entry.operation)] : null,
    insn.prefix ? [t('inspector', 'Prefixes'), `<span class="mono">${esc(insn.prefix)}</span>`] : null,
    [t('inspector', 'Address'), hex(addr)],
    [t('inspector', 'In'), where(p, addr)],
    [t('inspector', 'Encoding'), `<span class="mono">${esc(bytesOf(p, index))}</span>`],
    [t('inspector', 'Length'), tn('inspector', '{count} byte', '{count} bytes', insn.length)],
  ]);
  let html = `<section class="card">${head}<div class="insn-text">${esc(text)}</div>${desc}${rows}</section>`;
  if (p.mode === 64 && !data) {
    // The HLA64 line, from the instruction that starts it.
    const start = index > 0 && p.flags[index - 1]! & IF.FUSE ? index - 1 : index;
    const { line, fused } = x86HlaLine(p, start);
    html += hlaCard(line.words[0] === 'instruction' ? esc(line.text) : hlaHtml(line.text), fused ? t('inspector', 'This line stands for this instruction and the next one.') : '', line.words);
  }

  const table = p.tables.get(index);
  if (table) {
    const list = table.map((target, k) => `<div class="ref" data-goto="${target}"><span>${k}</span><span class="ref-fn">${esc(nameOf(p, target) ?? hex(target))}</span></div>`).join('');
    html += card(tn('inspector', 'Switch with {count} case', 'Switch with {count} cases', table.length), `<div class="reflist">${list}</div>`);
  } else if (insn.target !== undefined && insn.f & (F.BRANCH | F.CALL) && p.indexOf(insn.target) >= 0) {
    html += card(insn.f & F.CALL ? t('inspector', 'Calls') : t('inspector', 'Goes to'), `<div class="ref" data-goto="${insn.target}"><span>${insn.target.toString(16)}</span><span class="ref-fn">${esc(nameOf(p, insn.target) ?? hex(insn.target))}</span></div>`);
  }
  const dataAddr = p.addressAt.get(index);
  if (dataAddr !== undefined) html += dataCard(p, dataAddr);

  if (entry) {
    const key = catalogue().key(insn.m);
    const used = p.counts.filter((c) => catalogue().key(c.mnemonic) === key).reduce((n, c) => n + c.count, 0);
    html += formsCard(entry.forms, (form) => ({ url: form.url && catalogue().docUrl(form), label: '↗' }), key, used, 10);
  }
  return html;
}

function dataCard(p: X86Program, addr: number): string {
  const imported = p.importSlots.get(addr);
  const data = p.dataAt(addr);
  const refs = p.dataRefs.get(addr) ?? p.slotCallers.get(addr) ?? [];
  let body = '';
  if (imported) body += `<p class="mono">${esc(p.image.demangle(imported).full)}</p>`;
  else if (data?.kind === 'string') body += `<div class="pre">${esc(data.text)}</div>`;
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
  return card(imported ? t('inspector', 'Imported function') : data?.kind === 'string' ? t('inspector', 'String') : t('inspector', 'Data'), body);
}

function fnCard(p: X86Program, index: number): string {
  const fn = p.functions[index]!;
  const callers = p.callers.get(fn.addr) ?? [];
  const calls = new Map<number, number>();
  const imports = new Map<string, number>();
  const strings = new Map<number, string>();
  const limit = Math.min(fn.count, 20000);
  for (let i = fn.first; i < fn.first + limit; i++) {
    const addr = p.addressAt.get(i);
    if (p.flags[i]! & IF.CALL) {
      const insn = p.insn(i);
      if (insn.target !== undefined) calls.set(insn.target, (calls.get(insn.target) ?? 0) + 1);
      else if (addr !== undefined && p.importSlots.has(addr)) imports.set(p.importSlots.get(addr)!, (imports.get(p.importSlots.get(addr)!) ?? 0) + 1);
    }
    const data = addr !== undefined ? p.dataAt(addr) : undefined;
    if (addr !== undefined && data?.kind === 'string') strings.set(addr, data.text);
  }
  const bytes = fnBytes(p, index);
  let html = card(
    t('inspector', 'Function'),
    kv([
      [t('inspector', 'Name'), esc(fnName(fn))],
      fn.full !== fn.name ? [t('inspector', 'Full name'), esc(fn.full)] : null,
      fn.raw ? [t('inspector', 'Symbol'), esc(fn.raw)] : null,
      [t('inspector', 'Kind'), esc(kindLabel(fn.kind)) + (fn.language && fn.language !== 'other' ? ` · ${esc(fn.language)}` : '')],
      [t('inspector', 'Address'), `${hex(fn.addr)} – ${hex(fn.addr + bytes)}`],
      [t('inspector', 'Size'), `${tn('inspector', '{count} instruction', '{count} instructions', fn.count)} · ${tn('inspector', '{count} byte', '{count} bytes', bytes)}`],
    ]),
  );
  html += calledFromCard(p, callers);
  const callList = [...calls].sort((a, b) => b[1] - a[1]);
  const importList = [...imports].sort((a, b) => b[1] - a[1]);
  const callRows = [
    ...callList.map(([addr, n]) => `<div class="ref" data-goto="${addr}"><span>${n}×</span><span class="ref-fn">${esc(nameOf(p, addr) ?? hex(addr))}</span></div>`),
    ...importList.map(([name, n]) => `<div class="ref"><span>${n}×</span><span class="ref-fn">${esc(p.image.demangle(name).short)}</span></div>`),
  ];
  html += callsCard(callRows.length, callRows);
  html += stringsCard(strings);
  return html;
}

function labelCard(p: X86Program, index: number): string {
  return labelInfoCard(p, p.addrOf(index), `<p class="insn-desc">${esc(t('inspector', 'A place branches go to.'))}</p>`, branchesTo(p, index)) + instructionCard(p, index);
}

function importCard(p: X86Program, name: string, addr?: number): string {
  const fn = addr !== undefined ? p.functionAt(addr) : undefined;
  const raw = fn?.raw ?? name;
  const imp = p.image.imports.find((i) => i.name === raw || `_${i.name}` === raw || i.name === `_${raw}`);
  const callers = importCallers(p, imp?.name ?? raw, addr);
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

/** The details panel for whatever is selected in x86 code. */
export function x86Inspector(p: X86Program, sel: NonNullable<Selection>): string {
  switch (sel.kind) {
    case 'insn':
      return instructionCard(p, sel.index);
    case 'fn':
      return fnCard(p, sel.fn);
    case 'label':
      return labelCard(p, sel.index);
    case 'string':
      return p.importSlots.has(sel.addr) ? importCard(p, p.importSlots.get(sel.addr)!) : dataCard(p, sel.addr);
    case 'import':
      return importCard(p, sel.name, sel.addr);
  }
}

/** Where Enter goes from an instruction: a branch or call target, or the data it names. */
export function x86Follow(p: X86Program, index: number): { code?: number; mem?: number } {
  const [target] = p.branchTargets(index);
  if (target !== undefined) return { code: p.addrOf(target) };
  const insn = p.insn(index);
  if (insn.target !== undefined && insn.f & F.CALL) return { code: insn.target };
  const addr = p.addressAt.get(index) ?? p.codeAt.get(index);
  if (addr !== undefined) return p.indexOf(addr) >= 0 ? { code: addr } : { mem: addr };
  return {};
}
