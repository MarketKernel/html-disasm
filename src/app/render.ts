/**
 * The HTML of one listing row. Rows are drawn as strings — a screenful is a
 * few dozen of them, redrawn on every scroll — with the colours of the
 * instruction's kind and clickable names (data-addr) for everything that
 * points somewhere.
 */

import { F, formatOp, hex as hexOf, type Insn, type Op } from '../core/arm64/types';
import { lookup } from '../core/catalog';
import { mnemonicTip, wordTip } from './cards';
import { liftArm64, pairedAddress, rawInstruction, type HlaLine } from '../core/hla';
import { n, t, tn } from '../core/i18n';
import { sectionOf } from '../core/image';
import { IF, type Program } from '../core/program';
import { ROW, type Rows } from '../core/rows';
import { armProgram, context, fnName, program, settings } from './state';
import { isPatched } from './patch';
import { viewOf } from './views';
import { addrCell, clip, esc, hex } from './ui';

const COMPARES = /^(cmp|cmn|tst|ccmp|ccmn|fcmp|fcmpe|fccmp|fccmpe)$/;

export function mnemonicClass(insn: Insn): string {
  if (insn.f & F.UNKNOWN) return 'k-unknown';
  if (insn.f & F.CALL) return 'k-call';
  if (insn.f & (F.BRANCH | F.TRAP)) return 'k-branch';
  if (insn.f & (F.LOAD | F.STORE)) return 'k-mem';
  if (COMPARES.test(insn.m)) return 'k-cmp';
  const entry = lookup(insn.m);
  if (!entry) return '';
  if (entry.group === 'simd' || entry.group === 'fp') return 'k-simd';
  if (entry.group === 'system' || entry.category === 'hint' || entry.category === 'barrier') return 'k-sys';
  return '';
}

function nameFor(addr: number): { name: string; kind: string } | undefined {
  return context().target(addr);
}

function opHtml(op: Op): string {
  switch (op.k) {
    case 'reg':
      return `<span class="t-reg">${esc(op.r)}</span>`;
    case 'imm':
      return `<span class="t-imm">${esc(op.t)}</span>`;
    case 'label': {
      const target = nameFor(op.addr);
      if (target) return `<span class="t-name" data-addr="${op.addr}" data-tip="${esc(esc(hex(op.addr)))}">${esc(target.name)}</span>`;
      const inCode = program().indexOf(op.addr) >= 0;
      return inCode ? `<span class="t-name" data-addr="${op.addr}">${hexOf(op.addr)}</span>` : `<span class="t-imm">${hexOf(op.addr)}</span>`;
    }
    case 'mem': {
      const text = formatOp(op);
      return text.replace(/(#-?0x[0-9a-f]+|#-?\d+)|(\b[xw]\d+\b|\bsp\b|\bxzr\b|\bwzr\b)|([a-z]+(?= #)|\b[us]xt[wbhx]\b)/g, (_, num?: string, r?: string, ext?: string) =>
        num ? `<span class="t-imm">${num}</span>` : r ? `<span class="t-reg">${r}</span>` : `<span class="t-op">${ext}</span>`,
      );
    }
    case 'shift':
      return `<span class="t-op">${esc(op.t)}</span>`;
    case 'text':
      return /^\{/.test(op.t) ? op.t.replace(/v\d+\.\w+/g, (r) => `<span class="t-reg">${r}</span>`) : `<span class="t-op">${esc(op.t)}</span>`;
  }
}

/** An instruction in assembly: mnemonic, then operands. */
export function asmHtml(insn: Insn): string {
  const cls = mnemonicClass(insn);
  const ops = insn.ops.map(opHtml).join('<span class="t-op">, </span>');
  return `<span class="r-mn ${cls}" data-mn="${esc(insn.m)}" data-tip="${esc(mnemonicTip(insn.m, lookup(insn.m)))}">${esc(insn.m)}</span> <span class="r-ops">${ops}</span>`;
}

/** A comment for an assembly row: what an adrp pair or adr points at. */
function asmComment(p: Program, index: number, insn: Insn): string {
  let addr: number | undefined;
  if (index > 0 && p.flags[index - 1]! & IF.FUSE) {
    const prev = p.insn(index - 1);
    if (prev.m === 'adrp') addr = pairedAddress(p.words[index - 1]!, p.addrOf(index - 1), p.words[index]!, p.addrOf(index));
  }
  if (insn.m === 'adr') addr = insn.target;
  // A call through a register loaded from an import's slot names the import.
  const slot = p.slotCalls.get(index);
  if (slot !== undefined) return `<span class="r-comment">; <span class="t-name" data-mem="${slot}">${esc(p.image.demangle(p.importSlots.get(slot) ?? '').short)}</span></span>`;
  if (addr === undefined) return '';
  return dataComment(addr);
}

function dataComment(addr: number): string {
  const data = program().dataAt(addr);
  const target = nameFor(addr);
  if (data?.kind === 'string') return `<span class="r-comment">; <span class="t-string" data-addr="${addr}">${data.objc ? '@' : ''}${esc(JSON.stringify(clip(data.text)))}</span></span>`;
  if (target) return `<span class="r-comment">; <span class="t-name" data-addr="${addr}">${esc(target.name)}</span></span>`;
  if (data?.kind === 'symbol') return `<span class="r-comment">; ${esc(data.name)}</span>`;
  const section = sectionOf(armProgram().image, addr);
  return `<span class="r-comment">; ${hex(addr)}${section ? ` <span class="t-op">${esc(section.name)}+${(addr - section.addr).toString(16)}</span>` : ''}</span>`;
}


/* ------------------------------------------------------------------ *
 * HLA64
 * ------------------------------------------------------------------ */

const NEW_WORDS = new Map<string, string>([
  ['udiv', 'udiv'], ['umulh', 'mul-high'], ['smulh', 'mul-high'], ['sbits', 'bits'], ['ror', 'ror'], ['rev16', 'bit-builtins'],
  ['rev32', 'bit-builtins'], ['cls', 'bit-builtins'], ['ctz', 'bit-builtins'], ['popcount', 'bit-builtins'], ['cas', 'cas'],
  ['load_acquire', 'atomic-load-store'], ['store_release', 'atomic-load-store'], ['f64', 'float-extra'], ['f32', 'float-extra'],
  ['ufloat', 'float-extra'], ['uint', 'float-extra'], ['bitcast', 'float-extra'], ['fmin', 'float-extra'], ['fmax', 'float-extra'],
  ['trap', 'trap'], ['relaxed', 'atomic'], ['acquire', 'atomic'], ['release', 'atomic'], ['acq_rel', 'atomic'], ['seq_cst', 'atomic'],
]);
const BUILTINS = new Set(['sext8', 'sext16', 'sext32', 'zext8', 'zext16', 'zext32', 'clz', 'rbit', 'rev', 'float', 'int', 'sqrt', 'fabs', 'min', 'max', 'abs']);
const KEYWORDS = new Set(['if', 'goto', 'return', 'fn', 'push', 'pop', 'page']);
const TOKEN = /("(?:[^"\\]|\\.)*")|(`[^`]*`)|(\/\/.*$)|([<>]=?u)|(\b(?:u8|u16|u32|u64|i8|i16|i32|i64|f32|f64)(?=\[))|(\b[A-Za-z_][A-Za-z0-9_.]*\b)|(-?\b(?:0x[0-9a-f]+|\d+(?:\.\d+)?)\b)/gi;
const REGISTER = /^(?:[xw](?:[12]?\d|3[01])|sp|wsp|xzr|wzr|lr|fp|[bhsdqv](?:[12]?\d|3[01])|r[abcd]x|e[abcd]x|r[sd]i|e[sd]i|r[sb]p|e[sb]p|r(?:[89]|1[0-5])d?|xmm\d{1,2})$/;

/** HLA64 text with colours; `link` is the address names in the line lead to. */
export function hlaHtml(text: string, link?: number): string {
  const attr = link !== undefined ? ` data-addr="${link}"` : '';
  return text.replace(TOKEN, (match, string?: string, quoted?: string, comment?: string, unsigned?: string, type?: string, ident?: string, number?: string) => {
    if (string) return `<span class="t-string"${attr}>${esc(string)}</span>`;
    if (quoted) return `<span class="t-name"${attr} data-tip="${wordTip('quoted-name')}">${esc(quoted)}</span>`;
    if (comment) return `<span class="t-comment">${esc(comment)}</span>`;
    if (unsigned) return `<span class="t-new" data-tip="${wordTip('unsigned-compare')}">${esc(unsigned)}</span>`;
    if (type) return `<span class="t-type">${type}</span>`;
    if (ident) {
      if (REGISTER.test(ident)) return `<span class="t-reg">${ident}</span>`;
      if (KEYWORDS.has(ident)) return `<span class="t-kw">${ident}</span>`;
      if (/^L[0-9a-f]+$/.test(ident)) return `<span class="t-name"${attr}>${ident}</span>`;
      const id = NEW_WORDS.get(ident) ?? (ident.startsWith('atomic_') ? 'atomic' : undefined);
      if (id) return `<span class="t-new" data-tip="${wordTip(id)}">${ident}</span>`;
      if (BUILTINS.has(ident)) return `<span class="t-kw">${ident}</span>`;
      if (ident.startsWith('data_') || ident.startsWith('sub_') || ident.startsWith('got.')) return `<span class="t-name"${attr}>${esc(ident)}</span>`;
      return esc(ident);
    }
    if (number) return `<span class="t-imm">${number}</span>`;
    return esc(match);
  });
}

/** The HLA64 line of an instruction row (and the address its names lead to): joined with the next one when the analysis marked the pair. */
export function hlaLine(p: Program, index: number): { line: HlaLine; insn: Insn; link?: number; raw: boolean } {
  const insn = p.insn(index);
  const next = p.flags[index]! & IF.FUSE && index + 1 < p.totalInstructions ? { word: p.words[index + 1]!, pc: p.addrOf(index + 1) } : undefined;
  const line = liftArm64(p.words[index]!, p.addrOf(index), context(), next);
  return { line, insn, link: line.link, raw: !line.fused && line.words.length === 1 && line.words[0] === 'instruction' };
}

/* ------------------------------------------------------------------ *
 * Rows
 * ------------------------------------------------------------------ */

function bytesOf(word: number): string {
  const b = [word & 0xff, (word >>> 8) & 0xff, (word >>> 16) & 0xff, word >>> 24];
  return b.map((x) => x.toString(16).padStart(2, '0')).join(' ');
}


export function rowHtml(rows: Rows, r: number, selected: boolean): string {
  const own = viewOf(program()).rowHtml;
  if (own) return own(rows, r, selected);
  const p = armProgram();
  const kind = rows.kind[r]!;
  const value = rows.value[r]!;
  const hla = rows.mode === 'hla';
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
      const callers = p.callers.get(fn.addr)?.length ?? 0;
      const meta = [hex(fn.addr), tn('listing', '{count} instruction', '{count} instructions', fn.count), fn.kind === 'anonymous' ? '' : kindLabel(fn.kind), callers ? tn('listing', '{count} caller', '{count} callers', callers) : '']
        .filter(Boolean)
        .join(' · ');
      if (hla) {
        const words: string[] = [];
        const name = hlaNameOf(fnName(fn), words);
        return `<div class="row fn hla${sel}" data-row="${r}"><span class="r-code"><span class="t-kw">fn</span> <span class="t-name" data-addr="${fn.addr}">${esc(name)}</span>() {</span><span class="r-comment">// ${esc(meta)}</span></div>`;
      }
      return `<div class="row fn${sel}" data-row="${r}"><span class="fn-title" title="${esc(fn.full)}">${esc(fnName(fn))}</span><span class="fn-meta">${esc(meta)}</span></div>`;
    }
    case ROW.FN_END:
      return `<div class="row fn-end" data-row="${r}">}</div>`;
    case ROW.LABEL: {
      const addr = p.addrOf(value);
      return `<div class="row label${sel}" data-row="${r}">${hla ? '' : addrCell(addr)}${p.labelName(addr)}:</div>`;
    }
    case ROW.PAD: {
      const count = rows.span.get(r) ?? 1;
      return `<div class="row pad${sel}" data-row="${r}">${addrCell(p.addrOf(value))}${hla ? '<span class="r-indent"></span>' : ''}<span class="r-code">${asmHtml(p.insn(value))} <span class="t-op">× ${n(count)}</span></span><span class="r-comment">; ${esc(t('listing', 'padding'))}, ${esc(tn('inspector', '{count} byte', '{count} bytes', count * 4))}</span></div>`;
    }
  }
  const addr = p.addrOf(value);
  const bytes = settings.bytes ? `<span class="r-bytes">${bytesOf(p.words[value]!)}</span>` : '';
  const patched = isPatched(value) ? ' is-patched' : '';
  if (!hla) {
    const insn = p.insn(value);
    return `<div class="row${sel}${patched}" data-row="${r}">${addrCell(addr)}${bytes}<span class="r-code">${asmHtml(insn)}</span>${asmComment(p, value, insn)}</div>`;
  }
  const { line, insn, link, raw } = hlaLine(p, value);
  const code = raw ? asmHtml(insn) : hlaHtml(line.text, link);
  const comment = line.comment ? `<span class="r-comment">// ${esc(line.comment)}</span>` : '';
  return `<div class="row${sel}${patched}" data-row="${r}">${addrCell(addr)}${bytes}<span class="r-indent"></span><span class="r-code">${code}</span>${comment}</div>`;
}

function hlaNameOf(name: string, words: string[]): string {
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) return name;
  words.push('quoted-name');
  return `\`${name}\``;
}

export function kindLabel(kind: string): string {
  switch (kind) {
    case 'export':
      return t('fn', 'exported');
    case 'symbol':
      return t('fn', 'symbol');
    case 'import':
      return t('fn', 'imported');
    case 'entry':
      return t('fn', 'entry point');
  }
  return t('fn', 'no name');
}

export { rawInstruction };
