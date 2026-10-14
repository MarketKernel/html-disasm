/**
 * The page's WebAssembly parts: the rows of the listing (the text format with
 * names, indented by blocks, and HLA64 lines whose every name is a link), the
 * details panel for an instruction, a function, a label, a string or an
 * import, the Module page — every section and custom section of the file —
 * and the imports and exports.
 *
 * Links are data attributes the page's click handlers follow: data-addr for
 * code (or an import entry), data-mem for an address in linear memory,
 * data-goto in lists, data-import for an imported function, data-ref for the
 * reference.
 */

import { WASM_CATALOGUE } from '../core/catalog';
import { n, t, tn } from '../core/i18n';
import { ROW, type Rows } from '../core/rows';
import { bytesText, decodeAt, formatInsn, operandsText, WasmInsn } from '../core/wasm/decode';
import { liftGroup, parts, type Naming } from '../core/wasm/hla';
import { formatContext, limitsText, pageSize, signatureText, typeText, type FuncType, type WasmModule } from '../core/wasm/module';
import { IMM, opcodeText, W } from '../core/wasm/opcodes';
import type { ImportedFn, WasmProgram } from '../core/wasm/program';
import type { ValType } from '../core/wasm/reader';
import { branchesTo, calledFromCard, calleeRef, callsCard, card, formsCard, goesToCard, hlaCard, insnDesc, insnHead, joinedNote, kv, labelInfoCard, mnemonicTip, refList, stringsCard, table, where, wordTip } from './cards';
import { sizeLabel } from './labels';
import { fnName, settings, state, type Selection } from './state';
import { addrCell, esc, hex } from './ui';

const scratch = new WasmInsn();

/* ------------------------------------------------------------------ *
 * Names
 * ------------------------------------------------------------------ */

export function naming(p: WasmProgram): Naming {
  return { func: (index) => (p.func(index) ? fnName(p.func(index)!) : `func${index}`) };
}

/** The types of a function's locals, parameters first. */
function localTypes(p: WasmProgram, func: number): ValType[] {
  const types = [...(p.funcType(func)?.params ?? [])];
  const body = p.module.bodies[func - p.module.importedFuncs];
  for (const group of body?.locals ?? []) for (let k = 0; k < group.count && types.length < 100000; k++) types.push(group.type);
  return types;
}

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

function paramName(p: WasmProgram, func: number, index: number): string {
  const name = p.localName(func, index);
  return name && IDENTIFIER.test(name) ? name : `l${index}`;
}

/** `(l0: i32, l1: i32) -> i32` with the module's names for the parameters. */
function headerSignature(p: WasmProgram, func: number): string {
  const type = p.funcType(func);
  if (!type) return '()';
  const params = type.params.map((t, k) => `${paramName(p, func, k)}: ${t.text}`).join(', ');
  const results = type.results.length === 1 ? ` -> ${type.results[0]!.text}` : type.results.length ? ` -> (${type.results.map((r) => r.text).join(', ')})` : '';
  return `(${params})${results}`;
}

function sourceOf(p: WasmProgram, index: number): string | undefined {
  const line = p.lineOf(index);
  return line ? `${line.file.split('/').pop()}:${line.line}` : undefined;
}

/** The source line, shown on the first instruction of every new line. */
function sourceComment(p: WasmProgram, index: number): string {
  if (!p.lines) return '';
  const here = sourceOf(p, index);
  if (!here) return '';
  const fnStart = p.functions[p.functionOfIndex(index)]?.first ?? index;
  if (index > fnStart && sourceOf(p, index - 1) === here) return '';
  return here;
}

/* ------------------------------------------------------------------ *
 * Instructions in the text format
 * ------------------------------------------------------------------ */

export function wasmClass(insn: WasmInsn): string {
  const op = insn.op;
  if (!op) return 'k-unknown';
  if (op.flags & W.CALL) return 'k-call';
  if (op.flags & (W.BRANCH | W.END | W.RETURN)) return 'k-branch';
  if (op.flags & (W.LOAD | W.STORE)) return 'k-mem';
  if (op.flags & W.STRUCTURE) return 'k-sys';
  if (/\.(eqz?|ne|[lg][te](_[su])?)$/.test(insn.m)) return 'k-cmp';
  if (op.group === 'vector') return 'k-simd';
  return '';
}

const numbers = (text: string) => esc(text).replace(/(-?\b(?:0x[0-9a-f.]+(?:p[+-]\d+)?|\d+)\b)/gi, '<span class="t-imm">$1</span>');

function labelLink(p: WasmProgram, target: number): string {
  const addr = p.addrOf(target);
  return `<span class="t-name" data-addr="${addr}">${p.labelName(addr)}</span>`;
}

function funcLink(p: WasmProgram, index: number): string {
  const fn = p.func(index);
  const name = fn ? fnName(fn) : `func${index}`;
  return `<span class="t-name" data-addr="${fn?.addr ?? -1}" data-tip="${esc(esc(`func ${index}: ${signatureText(p.funcType(index))}`))}">$${esc(name)}</span>`;
}

/** A string at a constant the code uses, as a comment. */
function stringComment(p: WasmProgram, value: number | bigint): string {
  if (typeof value !== 'number' || value <= 0 || !p.dataRefs.has(value)) return '';
  const data = p.dataAt(value);
  if (data?.kind !== 'string') return '';
  return `<span class="t-string" data-mem="${value}">${esc(JSON.stringify(data.text.length > 100 ? `${data.text.slice(0, 100)}…` : data.text))}</span>`;
}

/** An instruction in the text format, names instead of indices; `comments` collects what goes after it. */
export function wasmAsmHtml(p: WasmProgram, index: number, insn: WasmInsn, comments: string[]): string {
  const op = insn.op;
  const head = `<span class="r-mn ${wasmClass(insn)}" data-mn="${esc(insn.m)}" data-tip="${esc(mnemonicTip(insn.m, WASM_CATALOGUE.lookup(insn.m)))}">${esc(insn.m)}</span>`;
  if (!op) return `${head} <span class="t-op">${esc(operandsText(insn).trim())}</span>`;
  const fn = p.functions[p.functionOfIndex(index)];
  const func = fn?.index ?? 0;
  let ops = '';
  switch (op.imm) {
    case IMM.LABEL: {
      ops = `<span class="t-imm">${insn.a}</span>`;
      const [target] = p.branchTargets(index);
      if (target !== undefined) comments.push(`→ ${labelLink(p, target)}`);
      break;
    }
    case IMM.BR_TABLE: {
      ops = numbers(insn.labels!.join(' '));
      const targets = [...new Set(p.branchTargets(index))];
      comments.push(`→ ${targets.slice(0, 6).map((target) => labelLink(p, target)).join(', ')}${targets.length > 6 ? ` … (${targets.length})` : ''}`);
      break;
    }
    case IMM.FUNC:
      ops = funcLink(p, insn.a);
      break;
    case IMM.CALL_INDIRECT: {
      const type = p.module.types[insn.a]?.func;
      ops = `${insn.b ? `${esc(p.tableName(insn.b))} ` : ''}<span class="t-op">(type <span class="t-imm">${insn.a}</span>)</span>`;
      comments.push(esc(signatureText(type)));
      break;
    }
    case IMM.LOCAL: {
      const name = p.localName(func, insn.a);
      const type = localTypes(p, func)[insn.a]?.text ?? '?';
      ops = `<span class="t-reg" data-tip="${esc(esc(`local ${insn.a}: ${type}`))}">${name ? `$${esc(name)}` : insn.a}</span>`;
      break;
    }
    case IMM.GLOBAL: {
      const global = p.module.globals[insn.a];
      const named = p.module.names.globals.get(insn.a);
      ops = `<span class="t-name" data-tip="${esc(esc(`global ${insn.a}: ${global?.mutable ? 'mut ' : ''}${global?.type.text ?? '?'}`))}">${named ? `$${esc(named)}` : insn.a}</span>`;
      break;
    }
    case IMM.I32:
    case IMM.I64: {
      ops = `<span class="t-imm">${insn.value}</span>`;
      const string = stringComment(p, insn.value);
      if (string) comments.push(string);
      break;
    }
    case IMM.F32:
    case IMM.F64: {
      const text = operandsText(insn).trim();
      const at = text.indexOf(' (;=');
      ops = `<span class="t-imm">${esc(at > 0 ? text.slice(0, at) : text)}</span>${at > 0 ? ` <span class="t-comment">${esc(text.slice(at + 1))}</span>` : ''}`;
      break;
    }
    case IMM.BLOCK:
    case IMM.TRY_TABLE:
      ops = `<span class="t-type">${esc(operandsText(insn, formatContext(p.module)).trim())}</span>`;
      break;
    default:
      ops = numbers(operandsText(insn, formatContext(p.module)).trim());
  }
  return ops ? `${head} <span class="r-ops">${ops}</span>` : head;
}

/** The text of an instruction with its names, for the details panel. */
function plainText(html: string): string {
  return html.replace(/<[^>]+>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
}

/* ------------------------------------------------------------------ *
 * HLA64 lines
 * ------------------------------------------------------------------ */

const NEW_WORDS = new Map<string, string>([
  ['udiv', 'udiv'], ['urem', 'udiv'], ['rotl', 'ror'], ['ror', 'ror'], ['ctz', 'bit-builtins'], ['popcount', 'bit-builtins'], ['cas', 'cas'],
  ['atomic_load', 'atomic-load-store'], ['atomic_store', 'atomic-load-store'], ['seq_cst', 'atomic'], ['fmin', 'float-extra'], ['fmax', 'float-extra'],
  ['bitcast', 'float-extra'], ['ceil', 'wasm-round'], ['floor', 'wasm-round'], ['trunc', 'wasm-round'], ['nearest', 'wasm-round'], ['copysign', 'wasm-round'],
  ['select', 'wasm-select'], ['_', 'wasm-drop'],
]);
const CONVERSIONS = /^(?:[iu](?:32|64)(?:_sat)?|f(?:32|64)u?)$/;
const BUILTINS = new Set(['sext8', 'sext16', 'sext32', 'clz', 'sqrt', 'fabs']);
const KEYWORDS = new Set(['if', 'else', 'goto', 'return', 'switch', 'case', 'default', 'fn', 'nan', 'inf']);
const TOKEN = /([<>]=?u\b)|(\b[a-z0-9_]+\.[a-z0-9_.]+)(<[^<>]*>)?(?=\()|(\b[A-Za-z_][A-Za-z0-9_]*\b)(?=\s*(\()?)|(-?\b(?:0x[0-9a-f]+|\d+(?:\.\d+)?(?:e[+-]?\d+)?)\b)|(\b(?:i8|u8|i16|u16|i32|u32|i64|u64|f32|f64)(?=\[))/gi;

function plainHtml(text: string): string {
  return text.replace(TOKEN, (match, unsigned?: string, folded?: string, imm?: string, ident?: string, callParen?: string, number?: string, type?: string) => {
    if (unsigned) return `<span class="t-new" data-tip="${wordTip('unsigned-compare')}">${esc(unsigned)}</span>`;
    if (folded) return `<span class="t-new" data-tip="${wordTip('wasm-folded')}" data-mn="${esc(folded)}">${esc(folded)}</span>${imm ? `<span class="t-imm">${esc(imm)}</span>` : ''}`;
    if (type) return `<span class="t-type">${type}</span>`;
    if (ident) {
      if (KEYWORDS.has(ident)) return `<span class="t-kw">${ident}</span>`;
      const id = NEW_WORDS.get(ident) ?? (ident.startsWith('atomic_') ? 'atomic' : callParen && CONVERSIONS.test(ident) ? 'wasm-convert' : undefined);
      if (id) return `<span class="t-new" data-tip="${wordTip(id)}">${ident}</span>`;
      if (BUILTINS.has(ident)) return `<span class="t-kw">${ident}</span>`;
      return esc(ident);
    }
    if (number) return `<span class="t-imm">${number}</span>`;
    return esc(match);
  });
}

/** An HLA64 line with its marks made into links and its words coloured. */
export function markedHtml(p: WasmProgram, text: string): string {
  return parts(text)
    .map((part) => {
      switch (part.kind) {
        case 'f': {
          const fn = p.funcAtAddr(part.value!);
          return `<span class="t-name" data-addr="${part.value}"${fn ? ` data-tip="${esc(esc(`func ${fn.index}: ${signatureText(p.funcType(fn.index!))}`))}"` : ''}>${esc(part.text)}</span>`;
        }
        case 'l':
          return `<span class="t-name" data-addr="${part.value}">${esc(part.text)}</span>`;
        case 's':
        case 'd':
          return `<span class="t-string" data-mem="${part.value}" data-tip="${esc(esc(hex(part.value!)))}">${esc(part.text)}</span>`;
        case 'v':
          return `<span class="t-reg">${esc(part.text)}</span>`;
        case 'g':
          return `<span class="t-name" data-tip="${esc(esc(`global ${part.value}`))}">${esc(part.text)}</span>`;
      }
      return plainHtml(part.text);
    })
    .join('');
}

/** The HLA64 line of a row, or the instructions as they are when it has none. */
export function wasmHlaLine(p: WasmProgram, first: number, last: number): { html: string; words: string[]; comment?: string; raw: boolean } {
  const line = liftGroup(p, first, last, naming(p));
  if (line) return { html: markedHtml(p, line.text), words: line.words, comment: line.comment, raw: false };
  const html: string[] = [];
  for (let i = first; i <= last; i++) html.push(wasmAsmHtml(p, i, p.insn(i), []));
  return { html: html.join('<span class="t-op">; </span>'), words: ['instruction'], raw: true };
}

/* ------------------------------------------------------------------ *
 * Rows
 * ------------------------------------------------------------------ */

const indent = (depth: number) => (depth ? `<span class="r-depth" style="width:${Math.min(depth, 40) * 2}ch"></span>` : '');

function fnMeta(p: WasmProgram, fnIndex: number): string {
  const fn = p.functions[fnIndex]!;
  const callers = p.callers.get(fn.addr)?.length ?? 0;
  const kind = fn.kind === 'export' ? t('fn', 'exported') : fn.kind === 'entry' ? t('fn', 'start function') : '';
  return [hex(fn.addr), `func ${fn.index}`, tn('listing', '{count} instruction', '{count} instructions', fn.count), kind, callers ? tn('listing', '{count} caller', '{count} callers', callers) : '']
    .filter(Boolean)
    .join(' · ');
}

export function wasmRowHtml(p: WasmProgram, rows: Rows, r: number, selected: boolean): string {
  const kind = rows.kind[r]!;
  const value = rows.value[r]!;
  const hla = rows.mode === 'hla';
  const sel = selected ? ' is-selected' : '';
  switch (kind) {
    case ROW.SECTION:
      return `<div class="row section" data-row="${r}">; ${esc(t('listing', 'code section'))} — ${esc(tn('listing', '{count} instruction', '{count} instructions', p.totalInstructions))}</div>`;
    case ROW.GAP:
      return `<div class="row gap" data-row="${r}"></div>`;
    case ROW.FN_HEADER: {
      const fn = p.functions[value]!;
      const name = fnName(fn);
      if (hla) {
        const shown = IDENTIFIER.test(name) ? name : `\`${name}\``;
        return `<div class="row fn hla${sel}" data-row="${r}"><span class="r-code"><span class="t-kw">fn</span> <span class="t-name" data-addr="${fn.addr}">${esc(shown)}</span>${esc(headerSignature(p, fn.index!))} {</span><span class="r-comment">// ${esc(fnMeta(p, value))}</span></div>`;
      }
      return `<div class="row fn${sel}" data-row="${r}"><span class="fn-title" title="${esc(fn.full)}">${esc(name)}</span><span class="fn-meta">${esc(`${signatureText(p.funcType(fn.index!))} · ${fnMeta(p, value)}`)}</span></div>`;
    }
    case ROW.FN_END:
      return `<div class="row fn-end" data-row="${r}">}</div>`;
    case ROW.LABEL: {
      const addr = p.addrOf(value);
      return `<div class="row label${sel}" data-row="${r}">${hla ? '' : addrCell(addr)}${p.labelName(addr)}:</div>`;
    }
  }
  const addr = p.addrOf(value);
  const insn = p.insn(value, scratch);
  const bytes = settings.bytes ? `<span class="r-bytes">${bytesText(p.module.bytes, insn, 4)}</span>` : '';
  const depth = p.depth[value]!;
  const comments: string[] = [];
  if (!hla) {
    const code = wasmAsmHtml(p, value, insn, comments);
    const source = sourceComment(p, value);
    if (source) comments.push(`<span class="t-comment">${esc(source)}</span>`);
    return `<div class="row${sel}" data-row="${r}">${addrCell(addr)}${bytes}${indent(depth)}<span class="r-code">${code}</span>${comments.length ? `<span class="r-comment">; ${comments.join(' ')}</span>` : ''}</div>`;
  }
  const last = p.joinedTo(value);
  const line = wasmHlaLine(p, value, last);
  const notes = [line.comment, sourceComment(p, value)].filter(Boolean) as string[];
  return `<div class="row${sel}" data-row="${r}">${addrCell(addr)}${bytes}<span class="r-indent"></span>${indent(depth)}<span class="r-code">${line.html}</span>${notes.length ? `<span class="r-comment">// ${esc(notes.join(' · '))}</span>` : ''}</div>`;
}

/* ------------------------------------------------------------------ *
 * Details panel
 * ------------------------------------------------------------------ */


/** A function in a list: a link into the code, or to the import. */
function fnRef(p: WasmProgram, index: number, left: string): string {
  const fn = p.func(index);
  return fn ? calleeRef(fn, left) : '';
}

/** The memory address an instruction reads or names, when it is a constant. */
function dataAddressOf(p: WasmProgram, index: number, insn: WasmInsn): number | undefined {
  if ((insn.m === 'i32.const' || insn.m === 'i64.const') && typeof insn.value === 'number' && p.dataRefs.has(insn.value)) return insn.value;
  if (insn.op && (insn.op.imm === IMM.MEMARG || insn.op.imm === IMM.MEMARG_LANE) && typeof insn.value === 'number') {
    const pc = p.addrOf(index);
    for (const [addr, refs] of p.dataRefs) if (refs.includes(pc) && addr >= insn.value) return addr;
  }
  return undefined;
}

function instructionCard(p: WasmProgram, index: number): string {
  const insn = p.insn(index, new WasmInsn());
  const entry = WASM_CATALOGUE.lookup(insn.m);
  const addr = p.addrOf(index);
  const fn = p.functions[p.functionOfIndex(index)];
  const comments: string[] = [];
  const asm = plainText(wasmAsmHtml(p, index, insn, comments));
  const head = insnHead(insn.m, wasmClass(insn), entry, insn.op ? '' : t('inspector', 'Not an instruction the decoder knows'));
  const desc = insnDesc(entry, t('inspector', 'These bytes do not decode to an instruction the decoder knows, so the rest of the function cannot be read: an instruction of a newer proposal, or a damaged module.'));
  const line = p.lineOf(index);
  const memory = insn.op && (insn.op.imm === IMM.MEMARG || insn.op.imm === IMM.MEMARG_LANE)
    ? `${tn('inspector', '{count} byte', '{count} bytes', insn.op.size)}, ${t('inspector', 'offset')} ${insn.value}, ${t('inspector', 'align')} ${2 ** insn.align}${insn.mem ? `, ${t('inspector', 'memory')} ${insn.mem}` : ''}`
    : '';
  let local = '';
  if (insn.op?.imm === IMM.LOCAL && fn) {
    const name = p.localName(fn.index!, insn.a);
    local = `${insn.a}${name ? ` (${esc(name)})` : ''}: ${esc(localTypes(p, fn.index!)[insn.a]?.text ?? '?')}${insn.a < (p.funcType(fn.index!)?.params.length ?? 0) ? ` · ${esc(t('inspector', 'parameter'))}` : ''}`;
  }
  const rows = kv([
    entry?.stack ? [t('inspector', 'Stack'), esc(entry.stack)] : null,
    entry?.operation ? [t('inspector', 'Does'), esc(entry.operation)] : null,
    local ? [t('inspector', 'Local'), local] : null,
    insn.op?.imm === IMM.GLOBAL ? [t('inspector', 'Global'), `${insn.a} (${esc(p.globalName(insn.a))}): ${esc(p.module.globals[insn.a]?.type.text ?? '?')}`] : null,
    memory ? [t('inspector', 'Memory'), esc(memory)] : null,
    [t('inspector', 'Offset'), hex(addr)],
    [t('inspector', 'In'), where(p, addr)],
    line ? [t('inspector', 'Source'), esc(`${line.file}:${line.line}${line.column ? `:${line.column}` : ''}`)] : null,
    insn.op ? [t('inspector', 'Opcode'), esc(opcodeText(insn.op.code))] : null,
    [t('inspector', 'Encoding'), esc(bytesText(p.module.bytes, insn, 24))],
  ]);
  let html = `<section class="card">${head}<div class="insn-text">${esc(asm)}</div>${desc}${rows}</section>`;

  // HLA64
  const [first, last] = p.joined(index);
  const hla = wasmHlaLine(p, first, last);
  html += hlaCard(`${hla.html}${hla.comment ? ` <span class="t-comment">// ${esc(hla.comment)}</span>` : ''}`, hla.raw ? '' : joinedNote(last - first + 1), hla.words);

  // Where it leads.
  html += goesToCard(p, [...new Set(p.branchTargets(index))]);
  if (insn.m === 'call' || insn.m === 'return_call' || insn.m === 'ref.func') {
    html += card(insn.m === 'ref.func' ? t('inspector', 'Refers to') : t('inspector', 'Calls'), `<div class="reflist">${fnRef(p, insn.a, `func ${insn.a}`)}</div><p class="hint mono">${esc(signatureText(p.funcType(insn.a)))}</p>`);
  }
  if (/call_indirect$/.test(insn.m)) {
    const reach = p.indirect.get(insn.a) ?? [];
    html += card(
      tn('inspector', 'May call {count} function', 'May call {count} functions', reach.length),
      `<p class="hint">${esc(t('inspector', 'The functions of this type that are in a table; which one runs depends on the index.'))} <span class="mono">${esc(signatureText(p.module.types[insn.a]?.func))}</span></p><div class="reflist">${reach.slice(0, 300).map((f) => fnRef(p, f, `func ${f}`)).join('')}</div>`,
    );
  }
  const data = dataAddressOf(p, index, insn);
  if (data !== undefined) html += dataCard(p, data);

  // Forms and the specification.
  if (entry) html += formsCard(entry.forms, (form) => ({ url: form.url, label: 'WebAssembly ↗' }), insn.m, p.counts.find((c) => c.mnemonic === insn.m)?.count ?? 0, Infinity);
  return html;
}

function dataCard(p: WasmProgram, addr: number): string {
  const data = p.dataAt(addr);
  const refs = p.dataRefs.get(addr) ?? [];
  const segment = p.segmentAt(addr);
  let body = '';
  if (data?.kind === 'string') body += `<div class="pre">${esc(data.text)}</div>`;
  else {
    const bytes = p.memoryAt(addr, 64);
    if (bytes?.length) body += `<div class="pre">${esc([...bytes].map((b) => b.toString(16).padStart(2, '0')).join(' '))}</div>`;
  }
  body += kv([
    [t('inspector', 'Address'), `${hex(addr)} <span class="hint">${esc(t('inspector', 'in linear memory'))}</span>`],
    segment ? [t('inspector', 'Segment'), `${esc(segment.name)} (${segment.index})${segment.passive ? ` · ${esc(t('inspector', 'passive, placed by memory.init'))}` : ''}`] : [t('inspector', 'Segment'), esc(t('inspector', 'none: memory the program fills in itself'))],
    segment ? [t('inspector', 'In the file'), hex(segment.start + (addr - segment.addr))] : null,
  ]);
  body += `<h3 style="margin-top:12px">${esc(tn('inspector', '{count} reference', '{count} references', refs.length))}</h3>${refList(p, refs)}`;
  return card(data?.kind === 'string' ? t('inspector', 'String') : t('inspector', 'Data'), body);
}

function fnCard(p: WasmProgram, fnIndex: number): string {
  const fn = p.functions[fnIndex]!;
  const index = fn.index!;
  const body = p.bodies[fnIndex]!;
  const type = p.funcType(index);
  const exports = p.module.exports.filter((e) => e.kind === 'func' && e.index === index).map((e) => e.name);
  const locals = new Map<string, number>();
  for (const group of body.locals) locals.set(group.type.text, (locals.get(group.type.text) ?? 0) + group.count);
  const params = (type?.params ?? []).map((t, k) => `${esc(paramName(p, index, k))}: ${esc(t.text)}`).join(', ');
  const line = p.lineOf(fn.first);
  const rows = kv([
    [t('inspector', 'Name'), esc(fnName(fn))],
    fn.full !== fn.name ? [t('inspector', 'Full name'), esc(fn.full)] : null,
    fn.raw && fn.raw !== fn.full ? [t('inspector', 'Symbol'), esc(fn.raw)] : null,
    [t('inspector', 'Index'), `func ${index}`],
    [t('inspector', 'Kind'), esc(fn.kind === 'entry' ? t('fn', 'start function') : fn.kind === 'export' ? t('fn', 'exported') : fn.kind === 'symbol' ? t('fn', 'named') : t('fn', 'no name')) + (fn.language && fn.language !== 'other' ? ` · ${esc(fn.language)}` : '')],
    exports.length ? [t('inspector', 'Exported as'), exports.map((e) => esc(JSON.stringify(e))).join(', ')] : null,
    [t('inspector', 'Type'), esc(signatureText(type))],
    params ? [t('inspector', 'Parameters'), params] : null,
    locals.size ? [t('inspector', 'Locals'), [...locals].map(([k, v]) => `${v} × ${esc(k)}`).join(', ')] : null,
    [t('inspector', 'Code'), `${hex(fn.addr)} – ${hex(body.end)}`],
    [t('inspector', 'Size'), `${tn('inspector', '{count} instruction', '{count} instructions', fn.count)} · ${tn('inspector', '{count} byte', '{count} bytes', body.end - body.offset)}`],
    line ? [t('inspector', 'Source'), esc(`${line.file}:${line.line}`)] : null,
  ]);
  let html = card(t('inspector', 'Function'), rows);
  const callers = p.callers.get(fn.addr) ?? [];
  html += calledFromCard(p, callers);
  const taken = p.refFuncs.get(fn.addr) ?? [];
  const inTable = (p.indirect.get(p.module.funcTypes[index] ?? -1) ?? []).includes(index);
  if (taken.length || inTable) {
    html += card(t('inspector', 'Called indirectly'), `<p class="hint">${esc(inTable ? t('inspector', 'It is in a table of functions: a call_indirect of its type may reach it.') : '')}</p>${taken.length ? refList(p, taken) : ''}`);
  }
  // Calls and strings, from its instructions.
  const calls = new Map<number, number>();
  const strings = new Map<number, string>();
  let indirect = 0;
  const insn = new WasmInsn();
  for (let i = fn.first; i < fn.first + Math.min(fn.count, 50000); i++) {
    decodeAt(p.module.bytes, p.offsets[i]!, body.end, insn);
    if (insn.m === 'call' || insn.m === 'return_call') calls.set(insn.a, (calls.get(insn.a) ?? 0) + 1);
    else if (insn.op && insn.op.flags & W.CALL) indirect++;
    else if (insn.m === 'i32.const' && typeof insn.value === 'number' && p.dataRefs.has(insn.value)) {
      const data = p.dataAt(insn.value);
      if (data?.kind === 'string') strings.set(insn.value, data.text);
    }
  }
  const callList = [...calls].sort((a, b) => b[1] - a[1]);
  html += callsCard(callList.length, callList.map(([f, count]) => fnRef(p, f, `${count}×`)), indirect ? tn('inspector', 'and {count} call through a table or a reference', 'and {count} calls through a table or a reference', indirect) : '');
  html += stringsCard(strings);
  return html;
}

function labelCard(p: WasmProgram, index: number): string {
  const loop = p.insn(index).m === 'loop';
  const what = loop ? t('inspector', 'The start of a loop: branches to it go round again.') : t('inspector', 'The end of a block: branches to it leave the block.');
  return labelInfoCard(p, p.addrOf(index), `<p class="insn-desc">${esc(what)}</p>`, branchesTo(p, index)) + instructionCard(p, index);
}

function importCard(p: WasmProgram, addr: number | undefined, name: string): string {
  const fn = p.imported.find((f) => f.addr === addr) ?? p.imported.find((f) => f.raw === name);
  if (!fn) return card(t('inspector', 'Imported function'), `<p>${esc(name)}</p>`);
  const callers = p.callers.get(fn.addr) ?? [];
  const rows = kv([
    [t('inspector', 'Name'), esc(fnName(fn))],
    [t('inspector', 'Module'), esc(fn.module)],
    [t('inspector', 'Field'), esc(fn.field)],
    [t('inspector', 'Index'), `func ${fn.index}`],
    [t('inspector', 'Type'), esc(signatureText(p.funcType(fn.index!)))],
    [t('inspector', 'Import entry'), hex(fn.addr)],
  ]);
  return card(t('inspector', 'Imported function'), rows) + calledFromCard(p, callers);
}

/** The details panel for whatever is selected in a WebAssembly program. */
export function wasmInspector(p: WasmProgram, sel: NonNullable<Selection>): string {
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
      return importCard(p, sel.addr, sel.name);
  }
}

/** Where Enter goes from an instruction: a branch target, a called function, data. */
export function wasmFollow(p: WasmProgram, index: number): { code?: number; mem?: number; import?: ImportedFn } {
  const [target] = p.branchTargets(index);
  if (target !== undefined) return { code: p.addrOf(target) };
  const insn = p.insn(index);
  if (insn.m === 'call' || insn.m === 'return_call' || insn.m === 'ref.func') {
    const fn = p.func(insn.a);
    if (fn?.kind === 'import') return { import: fn as ImportedFn };
    if (fn) return { code: fn.addr };
  }
  const data = dataAddressOf(p, index, insn);
  return data !== undefined ? { mem: data } : {};
}

/* ------------------------------------------------------------------ *
 * Imports and exports
 * ------------------------------------------------------------------ */

function exportTarget(p: WasmProgram, kind: string, index: number): string {
  switch (kind) {
    case 'func': {
      const fn = p.func(index);
      return `${fn ? esc(fnName(fn)) : `func ${index}`} <span class="hint">${esc(signatureText(p.funcType(index)))}</span>`;
    }
    case 'global': {
      const g = p.module.globals[index];
      return `global ${index}: ${g?.mutable ? 'mut ' : ''}${esc(g?.type.text ?? '?')}${g?.init ? ` = ${esc(g.init)}` : ''}`;
    }
    case 'memory': {
      const m = p.module.memories[index];
      return `memory ${index}${m ? `: ${esc(memoryText(m.limits))}` : ''}`;
    }
    case 'table': {
      const tb = p.module.tables[index];
      return `table ${index}${tb ? `: ${esc(tb.type.text)} ${esc(limitsText(tb.limits))}` : ''}`;
    }
  }
  return `${kind} ${index}`;
}

function memoryText(limits: WasmModule['memories'][number]['limits']): string {
  const size = pageSize(limits);
  const bytes = (pages: number | bigint) => sizeLabel(Number(pages) * size);
  return `${limitsText(limits)} ${t('overview', 'pages')} (${bytes(limits.min)}${limits.max !== undefined ? ` – ${bytes(limits.max)}` : ''})${limits.shared ? `, ${t('overview', 'shared')}` : ''}${limits.is64 ? ', 64-bit' : ''}`;
}

export function renderWasmImports(p: WasmProgram, page: HTMLElement): void {
  const module = p.module;
  const modules = new Map<string, number>();
  for (const imp of module.imports) modules.set(imp.module, (modules.get(imp.module) ?? 0) + 1);
  const fnByOffset = new Map(p.imported.map((f) => [f.addr, f]));
  const imports = module.imports
    .map((imp) => {
      const fn = fnByOffset.get(imp.offset);
      return { imp, fn, calls: fn ? p.callers.get(fn.addr)?.length ?? 0 : 0 };
    })
    .sort((a, b) => b.calls - a.calls || a.imp.module.localeCompare(b.imp.module) || a.imp.name.localeCompare(b.imp.name));
  const what = (imp: (typeof imports)[number]['imp']) => {
    if (imp.kind === 'func') return esc(signatureText(imp.type !== undefined ? module.types[imp.type]?.func : undefined));
    if (imp.kind === 'memory') return esc(memoryText(module.memories[imp.index]!.limits));
    if (imp.kind === 'global') return esc(`${module.globals[imp.index]?.mutable ? 'mut ' : ''}${module.globals[imp.index]?.type.text ?? ''}`);
    if (imp.kind === 'table') return esc(`${module.tables[imp.index]?.type.text ?? ''} ${limitsText(module.tables[imp.index]!.limits)}`);
    return '';
  };
  page.innerHTML = `
    <h2>${esc(t('imports', 'Imports and exports'))}</h2>
    <p class="lede">${esc(t('imports', 'What the module needs from its host — functions, memory, tables, globals, each from a named module — and what it offers back. Calls are counted in the code.'))}</p>
    <h3>${esc(tn('imports', '{count} module', '{count} modules', modules.size))}</h3>
    <table class="table"><thead><tr><th>${esc(t('imports', 'Module'))}</th><th>${esc(t('imports', 'Imports'))}</th></tr></thead><tbody>
    ${[...modules].map(([name, count]) => `<tr><td class="mono">${esc(name)}</td><td class="mono">${count}</td></tr>`).join('')}
    </tbody></table>
    <h3>${esc(tn('imports', '{count} import', '{count} imports', imports.length))}</h3>
    <table class="table" id="import-table"><thead><tr><th>${esc(t('imports', 'Name'))}</th><th>${esc(t('imports', 'Module'))}</th><th>${esc(t('imports', 'Kind'))}</th><th>${esc(t('imports', 'Type'))}</th><th style="text-align:right">${esc(t('imports', 'Calls'))}</th></tr></thead><tbody>
    ${imports
      .map(
        ({ imp, fn, calls }) =>
          `<tr class="clickable"${fn ? ` data-import="${fn.addr}"` : ''}><td class="mono">${esc(imp.name)}</td><td class="mono">${esc(imp.module)}</td><td>${esc(imp.kind)}</td><td class="mono">${what(imp)}</td><td class="mono" style="text-align:right">${calls || ''}</td></tr>`,
      )
      .join('')}
    </tbody></table>
    <h3>${esc(tn('imports', '{count} export', '{count} exports', module.exports.length))}</h3>
    <table class="table" id="export-table"><thead><tr><th>${esc(t('imports', 'Name'))}</th><th>${esc(t('imports', 'Kind'))}</th><th>${esc(t('imports', 'What'))}</th></tr></thead><tbody>
    ${module.exports
      .map((e) => {
        const fn = e.kind === 'func' ? p.func(e.index) : undefined;
        const attr = fn && fn.kind !== 'import' ? ` class="clickable" data-goto="${fn.addr}"` : fn ? ` class="clickable" data-import="${fn.addr}"` : '';
        return `<tr${attr}><td class="mono">${esc(e.name)}</td><td>${esc(e.kind)}</td><td class="mono">${exportTarget(p, e.kind, e.index)}</td></tr>`;
      })
      .join('')}
    </tbody></table>`;
}

/* ------------------------------------------------------------------ *
 * The Module page
 * ------------------------------------------------------------------ */

/** Who made the module, judging by what it imports, exports and carries. */
export function toolchain(module: WasmModule): string[] {
  const found: string[] = [];
  const imports = module.imports;
  const names = new Set([...imports.map((i) => i.name), ...module.exports.map((e) => e.name)]);
  const has = (re: RegExp) => [...names].some((n) => re.test(n));
  if (module.customs.some((c) => c.name.startsWith('go:')) || imports.some((i) => i.module === 'go' || i.module === 'gojs')) found.push('Go');
  if (has(/^_?emscripten_|^__em_|^_embind/) || module.dylink) found.push('Emscripten');
  if (imports.some((i) => i.module === 'wbg' || /^__wbg_|^__wbindgen_/.test(i.name)) || has(/^__wbindgen_/)) found.push('wasm-bindgen (Rust)');
  if (imports.some((i) => i.module.startsWith('wasi_'))) found.push(imports.some((i) => i.module === 'wasi_snapshot_preview1') ? 'WASI preview 1' : 'WASI');
  if (has(/^__assemblyscript|^__new$|^__pin$/) && imports.some((i) => i.module === 'env' && i.name === 'abort')) found.push('AssemblyScript');
  for (const producer of module.producers) {
    for (const value of producer.values) {
      const label = `${value.name}${value.version ? ` ${value.version}` : ''}`;
      if (producer.field === 'language' && !found.includes(label)) found.push(label);
    }
  }
  return found;
}

export function renderWasmModule(p: WasmProgram, page: HTMLElement): void {
  const module = p.module;
  const kind = module.linking ? t('overview', 'Relocatable object file') : module.dylink ? t('overview', 'Dynamic library (side module)') : t('overview', 'Module');
  const start = module.start !== undefined ? p.func(module.start) : undefined;
  const codeSection = module.sections.find((s) => s.id === 10);
  const dataBytes = module.data.reduce((sum, d) => sum + d.size, 0);
  const funcTypes = module.types.filter((d) => d.kind === 'func').length;
  const toolchains = toolchain(module);
  const producedBy = module.producers.filter((pr) => pr.field !== 'language').flatMap((pr) => pr.values.map((v) => `${v.name}${v.version ? ` ${v.version}` : ''}`));
  const info: (string[] | null)[] = [
    [t('overview', 'File'), esc(`${state.fileName} · ${sizeLabel(state.fileSize)}`)],
    [t('overview', 'Format'), esc(`WebAssembly ${t('overview', 'binary, version')} ${module.version}${module.memory64 ? ' · memory64' : ''}`)],
    [t('overview', 'Type'), esc(kind)],
    module.names.module ? [t('overview', 'Module name'), esc(module.names.module)] : null,
    toolchains.length ? [t('overview', 'Made with'), esc(toolchains.join(' · '))] : null,
    producedBy.length ? [t('overview', 'Built with'), esc(producedBy.join(', '))] : null,
    start ? [t('overview', 'Start function'), `<a href="#" data-goto="${start.addr}">${esc(fnName(start))}</a> (func ${module.start})`] : null,
    [t('overview', 'Functions'), esc(`${n(p.functions.length)} ${t('overview', 'defined')}, ${n(p.imported.length)} ${t('overview', 'imported')}`)],
    [t('overview', 'Code'), esc(`${sizeLabel(codeSection?.size ?? 0)}, ${tn('stats', '{count} instruction', '{count} instructions', p.totalInstructions)}`)],
    [t('overview', 'Data'), esc(`${sizeLabel(dataBytes)} ${t('overview', 'in')} ${tn('overview', '{count} segment', '{count} segments', module.data.length)}`)],
    [t('overview', 'Types'), esc(`${n(module.types.length)} (${n(funcTypes)} ${t('overview', 'function types')})`)],
    module.features.length ? [t('overview', 'Features'), esc(module.features.map((f) => `${f.prefix}${f.name}`).join(' '))] : null,
    p.lines ? [t('overview', 'Debug info'), esc(tn('overview', 'DWARF line tables for {count} file', 'DWARF line tables for {count} files', p.lines.files.length))] : module.debug.size ? [t('overview', 'Debug info'), esc([...module.debug.keys()].join(' '))] : null,
    module.sourceMappingUrl ? [t('overview', 'Source map'), esc(module.sourceMappingUrl)] : null,
    module.externalDebugInfo ? [t('overview', 'External debug info'), esc(module.externalDebugInfo)] : null,
    module.buildId ? [t('overview', 'Build ID'), esc(module.buildId)] : null,
    module.dylink ? [t('overview', 'Dynamic library'), esc(`${t('overview', 'memory')} ${sizeLabel(module.dylink.memorySize)}, ${t('overview', 'table')} ${module.dylink.tableSize}${module.dylink.needed.length ? `, ${t('overview', 'needs')} ${module.dylink.needed.join(', ')}` : ''}`)] : null,
    module.linking ? [t('overview', 'Symbols'), esc(`${n(module.linking.symbols.length)} · ${t('overview', 'relocations')}: ${module.relocations.map((r) => `${r.section} ${r.count}`).join(', ')}`)] : null,
    module.warnings.length ? [t('overview', 'Problems'), esc(module.warnings.join('; '))] : null,
  ];

  const sections = module.sections
    .map((s) => `<tr><td class="mono">${s.id}</td><td class="mono"><b>${esc(s.id ? s.name : `custom “${s.name}”`)}</b></td><td class="mono">${hex(s.offset)}</td><td class="mono">${sizeLabel(s.size)}</td><td class="mono">${s.count ?? ''}</td></tr>`)
    .join('');
  const memories = module.memories
    .map((m, i) => `<tr><td class="mono">${i}</td><td class="mono">${esc(module.names.memories.get(i) ?? '')}</td><td class="mono">${esc(memoryText(m.limits))}</td><td>${esc(m.imported ? t('overview', 'imported') : t('overview', 'defined'))}${module.exports.some((e) => e.kind === 'memory' && e.index === i) ? ` · ${esc(t('overview', 'exported'))}` : ''}</td></tr>`)
    .join('');
  const tables = module.tables
    .map((tb, i) => {
      const elems = module.elements.filter((e) => e.mode === 'active' && e.table === i).reduce((sum, e) => sum + e.funcs.length, 0);
      return `<tr><td class="mono">${i}</td><td class="mono">${esc(p.tableName(i))}</td><td class="mono">${esc(tb.type.text)} ${esc(limitsText(tb.limits))}</td><td class="mono">${elems || ''}</td><td>${esc(tb.imported ? t('overview', 'imported') : t('overview', 'defined'))}</td></tr>`;
    })
    .join('');
  const globals = module.globals
    .slice(0, 2000)
    .map(
      (g, i) =>
        `<tr><td class="mono">${i}</td><td class="mono">${esc(p.globalName(i))}</td><td class="mono">${g.mutable ? 'mut ' : ''}${esc(g.type.text)}</td><td class="mono">${esc(g.imported ? t('overview', 'imported') : g.init ?? '')}</td><td class="mono" style="text-align:right">${p.globalRefs.get(i)?.length ?? ''}</td></tr>`,
    )
    .join('');
  const typeUse = new Map<number, number>();
  for (const type of module.funcTypes) typeUse.set(type, (typeUse.get(type) ?? 0) + 1);
  const types = module.types
    .slice(0, 1500)
    .map((d, i) => `<tr><td class="mono">${i}</td><td class="mono">${esc(module.names.types.get(i) ?? '')}</td><td class="mono">${esc(typeText(d))}</td><td class="mono" style="text-align:right">${typeUse.get(i) ?? ''}</td></tr>`)
    .join('');
  const preview = (d: WasmModule['data'][number]) => {
    const bytes = module.bytes.subarray(d.start, d.start + Math.min(d.size, 48));
    return [...bytes].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '·')).join('');
  };
  const segments = module.data
    .slice(0, 2000)
    .map((d, i) => {
      const placed = p.segments.find((s) => s.index === i);
      const range = placed ? `${hex(placed.addr)} – ${hex(placed.end)}` : d.offset ?? '';
      return `<tr><td class="mono">${i}</td><td class="mono">${esc(module.names.data.get(i) ?? '')}</td><td>${esc(d.mode === 'passive' ? (placed ? t('overview', 'passive, placed by the start function') : t('overview', 'passive')) : t('overview', 'active'))}</td><td class="mono">${esc(range)}</td><td class="mono">${sizeLabel(d.size)}</td><td class="mono">${esc(preview(d))}</td></tr>`;
    })
    .join('');
  const elements = module.elements
    .map((e, i) => `<tr><td class="mono">${i}</td><td>${esc(e.mode)}</td><td class="mono">${e.mode === 'active' ? `${e.table} @ ${esc(e.offset ?? '')}` : ''}</td><td class="mono">${esc(e.type)}</td><td class="mono">${e.funcs.length}</td></tr>`)
    .join('');
  const customs = module.customs
    .map((c) => {
      let says = c.text ?? '';
      if (c.name === 'name') says = t('overview', '{functions} function names, {locals} functions with local names, {globals} globals, {data} data segments', { functions: module.names.functions.size, locals: module.names.locals.size, globals: module.names.globals.size, data: module.names.data.size });
      else if (c.name === 'producers') says = module.producers.map((pr) => `${pr.field}: ${pr.values.map((v) => `${v.name} ${v.version}`.trim()).join(', ')}`).join('; ');
      else if (c.name === 'target_features') says = module.features.map((f) => `${f.prefix}${f.name}`).join(' ');
      else if (c.name === '.debug_line' && p.lines) says = tn('overview', 'line tables for {count} file', 'line tables for {count} files', p.lines.files.length);
      return `<tr><td class="mono"><b>${esc(c.name)}</b></td><td class="mono">${hex(c.offset)}</td><td class="mono">${sizeLabel(c.size)}</td><td class="mono">${esc(says.length > 300 ? `${says.slice(0, 300)}…` : says)}</td></tr>`;
    })
    .join('');
  const files = p.lines ? p.lines.files.map((file) => `<div>${esc(file)}</div>`).join('') : '';

  page.innerHTML = `
    <h2>${esc(t('overview', 'WebAssembly module'))}</h2>
    <p class="lede">${esc(t('overview', 'Everything in the file besides the code: its types and imports, memory, tables and globals, the data it starts with, and the custom sections the tools left in it.'))}</p>
    ${kv(info).replace('class="kv"', 'class="kv" style="max-width:900px"')}
    <h3>${esc(tn('overview', '{count} section', '{count} sections', module.sections.length))}</h3>
    ${table(['#', t('overview', 'Section'), t('overview', 'File offset'), t('overview', 'Size'), t('overview', 'Entries')], sections)}
    ${memories ? `<h3>${esc(t('overview', 'Memory'))}</h3>${table(['#', t('overview', 'Name'), t('overview', 'Size'), ''], memories)}` : ''}
    ${tables ? `<h3>${esc(t('overview', 'Tables'))}</h3>${table(['#', t('overview', 'Name'), t('overview', 'Type'), t('overview', 'Functions'), ''], tables)}` : ''}
    ${globals ? `<h3>${esc(tn('overview', '{count} global', '{count} globals', module.globals.length))}</h3>${table(['#', t('overview', 'Name'), t('overview', 'Type'), t('overview', 'Value'), t('overview', 'Uses')], globals)}` : ''}
    ${types ? `<h3>${esc(tn('overview', '{count} type', '{count} types', module.types.length))}</h3>${table(['#', t('overview', 'Name'), t('overview', 'Type'), t('overview', 'Functions')], types)}` : ''}
    ${segments ? `<h3>${esc(tn('overview', '{count} data segment', '{count} data segments', module.data.length))}</h3>${table(['#', t('overview', 'Name'), t('overview', 'Kind'), t('overview', 'Address'), t('overview', 'Size'), t('overview', 'Starts with')], segments)}` : ''}
    ${elements ? `<h3>${esc(tn('overview', '{count} element segment', '{count} element segments', module.elements.length))}</h3>${table(['#', t('overview', 'Kind'), t('overview', 'Table and offset'), t('overview', 'Type'), t('overview', 'Entries')], elements)}` : ''}
    ${customs ? `<h3>${esc(tn('overview', '{count} custom section', '{count} custom sections', module.customs.length))}</h3>${table([t('overview', 'Name'), t('overview', 'File offset'), t('overview', 'Size'), t('overview', 'What it says')], customs)}` : ''}
    ${files ? `<h3>${esc(tn('overview', '{count} source file', '{count} source files', p.lines!.files.length))}</h3><div class="pre">${files}</div>` : ''}
  `;
}

/** The function the page opens at. */
export { entryOf } from '../core/wasm/program';
export type { FuncType };
export { formatInsn };
