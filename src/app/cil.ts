/**
 * The page's .NET parts: the rows of the listing (ILAsm as ildasm writes it,
 * each instruction at its offset in its method's IL, the try blocks and
 * handlers marked where they start), the details panel for an instruction, a
 * method, a label, a string of #US or a member of another assembly, the
 * Assembly page — the manifest, the metadata, the types — and the references
 * and imports.
 *
 * Links are data attributes the page's click handlers follow: data-addr for
 * code (an RVA) or a member of another assembly (its MemberRef token),
 * data-mem for a string (its #US token), data-goto in lists, data-import for
 * an imported member, data-ref for the reference.
 */

import { CIL_CATALOGUE, type Form } from '../core/catalog';
import { parts } from '../core/wasm/hla';
import { F, OPERAND, opcodeText } from '../core/cil/opcodes';
import { label, tokenTable, USER_STRING, type CilInsn, type CilProgram, type ImportedMember } from '../core/cil/program';
import { n, t, tn } from '../core/i18n';
import { ROW, type Rows } from '../core/rows';
import { branchesTo, calledFromCard, calleeRef, callsCard, card, formsCard, goesToCard, hlaCard, insnDesc, insnHead, joinedNote, kv, labelInfoCard, mnemonicTip, refList, stringsCard, table, where, wordTip } from './cards';
import { sizeLabel } from './labels';
import { fnName, settings, state, type Selection } from './state';
import { esc, hex } from './ui';

/* ------------------------------------------------------------------ *
 * Instructions
 * ------------------------------------------------------------------ */

export function cilClass(insn: CilInsn): string {
  const op = insn.op;
  if (!op) return 'k-unknown';
  if (op.flags & F.CALL) return 'k-call';
  if (op.flags & (F.BRANCH | F.RETURN | F.THROW | F.END)) return 'k-branch';
  if (op.flags & (F.LOAD | F.STORE)) return 'k-mem';
  if (op.flags & F.COMPARE) return 'k-cmp';
  if (op.flags & F.PREFIX) return 'k-sys';
  return '';
}

/** Where an IL offset of the method an instruction is in lands: its RVA. */
function targetAddr(p: CilProgram, index: number, offset: number): number {
  const fn = p.functions[p.functionOfIndex(index)];
  return fn ? fn.addr + offset : -1;
}

function labelLink(p: CilProgram, index: number, offset: number): string {
  return `<span class="t-name" data-addr="${targetAddr(p, index, offset)}">${label(offset)}</span>`;
}

/** A string as a comment, when ildasm writes it as bytes. */
function stringComment(insn: CilInsn): string {
  const text = insn.string;
  if (text === null || insn.plain) return '';
  return `<span class="t-string" data-mem="${insn.a}">${esc(JSON.stringify(text.length > 100 ? `${text.slice(0, 100)}…` : text))}</span>`;
}

/** An instruction with its operand made into links; `comments` collects what goes after it. */
export function cilAsmHtml(p: CilProgram, index: number, insn: CilInsn, comments: string[]): string {
  const op = insn.op;
  const head = `<span class="r-mn ${cilClass(insn)}" data-mn="${esc(insn.m)}" data-tip="${esc(mnemonicTip(insn.m, CIL_CATALOGUE.lookup(insn.m)))}">${esc(insn.m)}</span>`;
  if (!op) return `${head} <span class="t-imm">${esc(insn.operand)}</span>`;
  const pad = (html: string) => `${head} <span class="r-ops">${html}</span>`;
  switch (op.operand) {
    case OPERAND.NONE:
      return head;
    case OPERAND.BR8:
    case OPERAND.BR32:
      return pad(labelLink(p, index, insn.a));
    case OPERAND.SWITCH:
      return pad(`( ${(insn.targets ?? []).map((offset) => labelLink(p, index, offset)).join(', ')})`);
    case OPERAND.VAR8:
    case OPERAND.VAR16:
      return pad(`<span class="t-reg">${esc(insn.operand)}</span>`);
    case OPERAND.METHOD: {
      const addr = insn.callee ?? undefined;
      const text = esc(insn.operand);
      return pad(addr === undefined ? `<span class="t-type">${text}</span>` : `<span class="t-name" data-addr="${addr}">${text}</span>`);
    }
    case OPERAND.STRING: {
      const comment = stringComment(insn);
      if (comment) comments.push(comment);
      return pad(`<span class="t-string" data-mem="${insn.a}">${esc(insn.operand)}</span>`);
    }
    case OPERAND.FIELD:
    case OPERAND.TYPE:
    case OPERAND.TOKEN:
    case OPERAND.SIG:
      return pad(`<span class="t-type">${esc(insn.operand)}</span>`);
  }
  return pad(`<span class="t-imm">${esc(insn.operand)}</span>`);
}

/* ------------------------------------------------------------------ *
 * HLA64 lines
 * ------------------------------------------------------------------ */

/** The words a line's plain text may hold, and the HLA64 word that explains each. */
const NEW_WORDS = new Map<string, string>([
  ['udiv', 'udiv'], ['urem', 'udiv'], ['len', 'cil-array'], ['new', 'cil-new'], ['null', 'cil-new'], ['_', 'cil-pop'], ['this', 'cil-local'],
]);
const CONVERSIONS = /^(?:[iu](?:8|16|32|64)|nu?int|f32|f64u?)$/;
const KEYWORDS = new Set(['if', 'goto', 'return', 'switch', 'case', 'nan', 'inf']);
const TOKEN = /([<>]=?u\b)|(\b[a-z][a-z0-9]*(?:\.[a-z0-9]+)+\b|\b(?:box|unbox|castclass|isinst|sizeof|initobj|ldobj|stobj|cpobj|mkrefany|refanyval|refanytype|localloc|cpblk|initblk|arglist|ckfinite|throw|ldtoken|ldvirtftn|newarr|ldelem|stelem)\b)(?=[<(])|(\b[A-Za-z_][A-Za-z0-9_]*\b)(?=\s*(\()?)|(-?\b(?:0x[0-9a-f]+|\d+(?:\.\d+)?(?:e[+-]?\d+)?)\b)|(\b(?:i8|u8|i16|u16|i32|u32|i64|f32|f64)(?=\[))/gi;

/** One token of a line's plain text, coloured. */
function tokenHtml(match: string, unsigned?: string, folded?: string, ident?: string, callParen?: string, number?: string, type?: string): string {
  if (unsigned) return `<span class="t-new" data-tip="${wordTip('unsigned-compare')}">${esc(unsigned)}</span>`;
  if (folded) return `<span class="t-new" data-tip="${wordTip('cil-folded')}" data-mn="${esc(folded)}">${esc(folded)}</span>`;
  if (type) return `<span class="t-type">${type}</span>`;
  if (ident) {
    if (KEYWORDS.has(ident)) return `<span class="t-kw">${ident}</span>`;
    const id = NEW_WORDS.get(ident) ?? (callParen && CONVERSIONS.test(ident) ? 'cil-convert' : undefined);
    if (id) return `<span class="t-new" data-tip="${wordTip(id)}">${ident}</span>`;
    return esc(ident);
  }
  if (number) return `<span class="t-imm">${number}</span>`;
  return esc(match);
}

/** A line's plain text: its tokens coloured, everything between them escaped (a generic's `<…>` too). */
function plainHtml(text: string): string {
  let out = '';
  let at = 0;
  for (const m of text.matchAll(TOKEN)) {
    out += esc(text.slice(at, m.index)) + tokenHtml(m[0], ...(m.slice(1) as (string | undefined)[]));
    at = m.index + m[0].length;
  }
  return out + esc(text.slice(at));
}

/** An HLA64 line with its marks made into links and its words coloured. */
export function cilMarkedHtml(p: CilProgram, text: string): string {
  return parts(text)
    .map((part) => {
      switch (part.kind) {
        case 'f':
          return `<span class="t-name" data-addr="${part.value}">${esc(part.text)}</span>`;
        case 'l':
          return `<span class="t-name" data-addr="${part.value}">${esc(part.text)}</span>`;
        case 's':
          return `<span class="t-string" data-mem="${part.value}">${esc(part.text)}</span>`;
        case 'v':
          return `<span class="t-reg">${esc(part.text)}</span>`;
        case 'g':
          return `<span class="t-name" data-tip="${esc(esc(p.fieldName(part.value!)))}">${esc(part.text)}</span>`;
      }
      return plainHtml(part.text);
    })
    .join('');
}

/** The HLA64 line of a row, or the instructions as they are when it has none. */
export function cilHlaLine(p: CilProgram, first: number, last: number): { html: string; words: string[]; raw: boolean } {
  const line = p.hla(first, last);
  if (line) return { html: cilMarkedHtml(p, line.text), words: line.words, raw: false };
  const html: string[] = [];
  for (let i = first; i <= last; i++) html.push(cilAsmHtml(p, i, p.insn(i), []));
  return { html: html.join('<span class="t-op">; </span>'), words: ['instruction'], raw: true };
}

/** `fn Name(args: string[]) -> int32 {`: the header of a method in the HLA64 view. */
function hlaHeader(p: CilProgram, fnIndex: number): string {
  const fn = p.functions[fnIndex]!;
  const method = p.method(fnIndex);
  const params = method.params.map(([name, type]) => `${esc(name)}: <span class="t-type">${esc(type)}</span>`).join(', ');
  const name = fnName(fn);
  const shown = /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) ? name : `\`${name}\``;
  return `<span class="t-kw">fn</span> <span class="t-name" data-addr="${fn.addr}">${esc(shown)}</span>(${params})${method.ret !== 'void' ? ` -&gt; <span class="t-type">${esc(method.ret)}</span>` : ''} {`;
}

/* ------------------------------------------------------------------ *
 * Exception handling
 * ------------------------------------------------------------------ */

/** What starts at an instruction: `.try`, `catch [System.Runtime]System.Exception`, `finally`, `filter`. */
function regionText(p: CilProgram, index: number): string {
  return p
    .regionsAt(index)
    .map(({ clause, part }) => {
      if (part === 'try') return '.try';
      if (part === 'filter') return 'filter';
      if (clause.kind & 1) return 'handler';
      if (clause.kind & 2) return 'finally';
      if (clause.kind & 4) return 'fault';
      return `catch ${clause.catch}`;
    })
    .join(' · ');
}

/* ------------------------------------------------------------------ *
 * Rows
 * ------------------------------------------------------------------ */

function fnMeta(p: CilProgram, fnIndex: number): string {
  const fn = p.functions[fnIndex]!;
  const callers = p.callers.get(fn.addr)?.length ?? 0;
  const kind = fn.kind === 'entry' ? t('fn', 'entry point') : fn.kind === 'export' ? t('fn', 'public') : '';
  return [hex(fn.addr), tn('listing', '{count} instruction', '{count} instructions', fn.count), kind, callers ? tn('listing', '{count} caller', '{count} callers', callers) : ''].filter(Boolean).join(' · ');
}

export function cilRowHtml(p: CilProgram, rows: Rows, r: number, selected: boolean): string {
  const kind = rows.kind[r]!;
  const value = rows.value[r]!;
  const hla = rows.mode === 'hla';
  const sel = selected ? ' is-selected' : '';
  switch (kind) {
    case ROW.SECTION: {
      const range = p.ranges[value]!;
      return `<div class="row section" data-row="${r}">; ${esc(range.name)} — ${esc(tn('listing', '{count} instruction', '{count} instructions', range.count))}</div>`;
    }
    case ROW.GAP:
      return `<div class="row gap" data-row="${r}"></div>`;
    case ROW.FN_HEADER: {
      const fn = p.functions[value]!;
      if (hla) return `<div class="row fn hla${sel}" data-row="${r}"><span class="r-code">${hlaHeader(p, value)}</span><span class="r-comment">// ${esc(fnMeta(p, value))}</span></div>`;
      return `<div class="row fn${sel}" data-row="${r}"><span class="fn-title" title="${esc(fn.full)}">${esc(fnName(fn))}</span><span class="fn-meta">${esc(`${p.method(value).signature} · ${fnMeta(p, value)}`)}</span></div>`;
    }
    case ROW.FN_END:
      return `<div class="row fn-end" data-row="${r}">}</div>`;
    case ROW.LABEL: {
      const regions = regionText(p, value);
      return `<div class="row label${sel}" data-row="${r}">${label(p.addrOf(value) - (p.functions[p.functionOfIndex(value)]?.addr ?? 0))}:${regions ? `<span class="r-comment">// ${esc(regions)}</span>` : ''}</div>`;
    }
  }
  const insn = p.insn(value);
  const fn = p.functions[p.functionOfIndex(value)];
  const offset = p.addrOf(value) - (fn?.addr ?? 0);
  const bytes = settings.bytes ? `<span class="r-bytes">${insn.bytes5}</span>` : '';
  const addr = `<span class="r-addr" title="RVA ${hex(p.addrOf(value))}">${label(offset)}</span>`;
  if (hla) {
    const last = p.joinedTo(value);
    return `<div class="row${sel}" data-row="${r}">${addr}${bytes}<span class="r-indent"></span><span class="r-code">${cilHlaLine(p, value, last).html}</span></div>`;
  }
  const comments: string[] = [];
  const code = cilAsmHtml(p, value, insn, comments);
  return `<div class="row${sel}" data-row="${r}">${addr}${bytes}<span class="r-code">${code}</span>${comments.length ? `<span class="r-comment">// ${comments.join(' ')}</span>` : ''}</div>`;
}

/* ------------------------------------------------------------------ *
 * Details panel
 * ------------------------------------------------------------------ */

const tokenHex = (tok: number) => `0x${tok.toString(16).padStart(8, '0')}`;

function instructionCard(p: CilProgram, index: number): string {
  const insn = p.insn(index);
  const entry = CIL_CATALOGUE.lookup(insn.m);
  const addr = p.addrOf(index);
  const fn = p.functions[p.functionOfIndex(index)];
  const offset = addr - (fn?.addr ?? 0);
  const head = insnHead(insn.m, cilClass(insn), entry, insn.op ? '' : t('inspector', 'Not an instruction the decoder knows'));
  const desc = insnDesc(entry, t('inspector', 'This byte is not a CIL opcode, or its operand runs past the end of the method: the method body is damaged, or it is not IL at all.'));
  const op = insn.op;
  const isToken = op && op.operand >= OPERAND.METHOD;
  const rows = kv([
    entry?.stack ? [t('inspector', 'Stack'), esc(entry.stack)] : null,
    entry?.operation ? [t('inspector', 'Does'), esc(entry.operation)] : null,
    isToken ? [t('inspector', 'Token'), `${tokenHex(insn.a)} <span class="hint">${esc(insn.tokenKind)}</span>`] : null,
    [t('inspector', 'Offset'), `${label(offset)} · RVA ${hex(addr)} · ${t('inspector', 'file')} ${hex(insn.fileOffset)}`],
    [t('inspector', 'In'), where(p, addr, label)],
    op ? [t('inspector', 'Opcode'), esc(opcodeText(op.code))] : null,
    [t('inspector', 'Encoding'), esc(insn.bytes24)],
  ]);
  let html = `<section class="card">${head}<div class="insn-text">${esc(insn.text)}</div>${desc}${rows}</section>`;

  // HLA64
  const [first, last] = p.joined(index);
  const hla = cilHlaLine(p, first, last);
  html += hlaCard(hla.html, hla.raw ? '' : joinedNote(last - first + 1), hla.words);
  html += goesToCard(p, [...new Set(p.branchTargets(index))]);
  if (op?.operand === OPERAND.METHOD) {
    const callee = p.callee(insn);
    const title = op.flags & F.CALL ? t('inspector', 'Calls') : t('inspector', 'Refers to');
    const where = callee?.kind === 'import' ? `<p class="hint">${esc(t('inspector', 'A member of another assembly: {assembly}', { assembly: (callee as ImportedMember).assembly || '?' }))}</p>` : '';
    html += card(title, `${callee ? `<div class="reflist">${calleeRef(callee, callee.kind === 'import' ? 'ref' : callee.addr.toString(16))}</div>` : ''}<p class="hint mono">${esc(insn.operand)}</p>${where}`);
  }
  if (op?.operand === OPERAND.STRING) html += stringCard(p, insn.a);
  if (insn.field !== null) {
    const refs = p.fieldRefs.get(insn.a) ?? [];
    html += card(t('inspector', 'Field'), `<p class="hint mono">${esc(insn.field)}</p><h3 style="margin-top:12px">${esc(tn('inspector', 'Used in {count} place', 'Used in {count} places', refs.length))}</h3>${refList(p, refs, label)}`);
  }
  // The protected blocks and handlers it is in.
  const clauses = p.clausesOf(index).filter((c) => (offset >= c.tryStart && offset < c.tryEnd) || (offset >= c.handlerStart && offset < c.handlerEnd) || (c.kind & 1 && offset >= c.filterStart && offset < c.handlerStart));
  if (clauses.length) {
    html += card(t('inspector', 'Exception handling'), `<p class="hint">${esc(t('inspector', 'The protected blocks and handlers this instruction is in.'))}</p>${clauses.map((c) => `<div class="syntax">${esc(c.text)}</div>`).join('')}`);
  }
  if (entry) {
    const link = (form: Form) => ({ url: form.url, label: `${form.url.includes('learn.microsoft.com') ? 'Microsoft Learn' : 'ECMA-335'} ↗` });
    html += formsCard(entry.forms, link, insn.m, p.counts.find((c) => c.mnemonic === insn.m)?.count ?? 0, Infinity);
  }
  return html;
}

function stringCard(p: CilProgram, tok: number): string {
  const data = p.dataAt(tok);
  const text = data?.kind === 'string' ? data.text : '';
  const refs = p.dataRefs.get(tok) ?? [];
  const body =
    `<div class="pre">${esc(text)}</div>` +
    kv([
      [t('inspector', 'Token'), `${tokenHex(tok)} <span class="hint">#US</span>`],
      [t('inspector', 'Length'), tn('inspector', '{count} character', '{count} characters', text.length)],
      [t('inspector', 'In ILAsm'), `<span class="mono">${esc(p.stringText(tok))}</span>`],
    ]) +
    `<h3 style="margin-top:12px">${esc(tn('inspector', '{count} reference', '{count} references', refs.length))}</h3>${refList(p, refs, label)}`;
  return card(t('inspector', 'String'), body);
}

function fnCard(p: CilProgram, fnIndex: number): string {
  const fn = p.functions[fnIndex]!;
  const method = p.method(fnIndex);
  const locals = method.locals;
  const rows = kv([
    [t('inspector', 'Name'), esc(fnName(fn))],
    [t('inspector', 'Signature'), `<span class="mono">${esc(fn.full)}</span>`],
    [t('inspector', 'Token'), tokenHex(method.token)],
    [t('inspector', 'Kind'), esc(fn.kind === 'entry' ? t('fn', 'entry point') : fn.kind === 'export' ? t('fn', 'public') : t('fn', 'named'))],
    [t('inspector', 'Attributes'), `<span class="mono">${esc(method.attributes)}</span>`],
    [t('inspector', 'Code'), `RVA ${hex(method.rva)} · ${t('inspector', 'IL from')} ${hex(fn.addr)}`],
    [t('inspector', 'Size'), `${tn('inspector', '{count} instruction', '{count} instructions', fn.count)} · ${tn('inspector', '{count} byte', '{count} bytes', method.size)}`],
    [t('inspector', 'Header'), esc(method.fat ? `${t('inspector', 'fat')} · .maxstack ${method.maxStack}${method.initLocals ? ' · init locals' : ''}` : `${t('inspector', 'tiny')} · .maxstack 8`)],
    locals.length ? [t('inspector', 'Locals'), `<div class="mono">${locals.slice(0, 200).map((type, k) => esc(`V_${k}: ${type}`)).join('<br>')}${locals.length > 200 ? '<br>…' : ''}</div>`] : null,
  ]);
  let html = card(t('inspector', 'Method'), rows);
  if (method.clauses.length) {
    html += card(tn('inspector', '{count} exception clause', '{count} exception clauses', method.clauses.length), method.clauses.map((c) => `<div class="syntax">${esc(c.text)}</div>`).join(''));
  }
  const callers = p.callers.get(fn.addr) ?? [];
  html += calledFromCard(p, callers, label);
  const taken = p.dataRefs.get(fn.addr) ?? [];
  if (taken.length) html += card(t('inspector', 'Taken as a delegate or function pointer'), refList(p, taken, label));
  // Calls and strings: the core reads its instructions in one go.
  const refs = p.functionRefs(fnIndex);
  const calls = new Map<number, number>();
  const strings = new Map<number, string>();
  for (const addr of refs.calls) calls.set(addr, (calls.get(addr) ?? 0) + 1);
  for (const [tok, text] of refs.strings) strings.set(tok, text);
  const indirect = refs.indirect;
  const callList = [...calls].sort((a, b) => b[1] - a[1]);
  const lookupFn = (addr: number) => p.importByToken.get(addr) ?? p.functionAt(addr);
  const callRows = callList.map(([addr, count]) => {
    const callee = lookupFn(addr);
    return callee ? calleeRef(callee, `${count}×`) : '';
  });
  html += callsCard(callList.length, callRows, indirect ? tn('inspector', 'and {count} call through a function pointer', 'and {count} calls through a function pointer', indirect) : '');
  html += stringsCard(strings);
  return html;
}

function labelCard(p: CilProgram, index: number): string {
  const regions = p.regionsAt(index).map(({ clause }) => `<div class="syntax">${esc(clause.text)}</div>`).join('');
  const what = regions ? `<p class="insn-desc">${esc(t('inspector', 'A protected block or a handler starts here.'))}</p>${regions}` : '';
  return labelInfoCard(p, p.addrOf(index), what, branchesTo(p, index), label) + instructionCard(p, index);
}

function importCard(p: CilProgram, addr: number | undefined): string {
  const member = addr === undefined ? undefined : p.importByToken.get(addr);
  if (!member) return card(t('inspector', 'Imported function'), '');
  const callers = p.callers.get(member.addr) ?? [];
  const used = member.field ? p.fieldRefs.get(member.addr) ?? [] : [...callers, ...(p.dataRefs.get(member.addr) ?? [])].sort((a, b) => a - b);
  const rows = kv([
    [t('inspector', 'Name'), esc(fnName(member))],
    [t('inspector', 'In ILAsm'), `<span class="mono">${esc(member.full)}</span>`],
    [t('inspector', 'Assembly'), esc(member.assembly || '—')],
    [t('inspector', 'Kind'), esc(member.field ? t('inspector', 'field') : t('inspector', 'method'))],
    [t('inspector', 'Token'), `${tokenHex(member.token)} <span class="hint">MemberRef</span>`],
  ]);
  return card(t('inspector', 'Member of another assembly'), rows) + card(tn('inspector', 'Used in {count} place', 'Used in {count} places', used.length), refList(p, used, label));
}

/** The details panel for whatever is selected in a .NET assembly. */
export function cilInspector(p: CilProgram, sel: NonNullable<Selection>): string {
  switch (sel.kind) {
    case 'insn':
      return instructionCard(p, sel.index);
    case 'fn':
      return fnCard(p, sel.fn);
    case 'label':
      return labelCard(p, sel.index);
    case 'string':
      return tokenTable(sel.addr) === USER_STRING ? stringCard(p, sel.addr) : card(t('inspector', 'Data'), `<p class="hint">${hex(sel.addr)}</p>`);
    case 'import':
      return importCard(p, sel.addr);
  }
}

/** Where Enter goes from an instruction: a branch target, a called method, a string. */
export function cilFollow(p: CilProgram, index: number): { code?: number; mem?: number; import?: ImportedMember } {
  const [target] = p.branchTargets(index);
  if (target !== undefined) return { code: p.addrOf(target) };
  const insn = p.insn(index);
  if (insn.op?.operand === OPERAND.METHOD) {
    const callee = p.callee(insn);
    if (callee?.kind === 'import') return { import: callee as ImportedMember };
    if (callee) return { code: callee.addr };
  }
  if (insn.op?.operand === OPERAND.STRING) return { mem: insn.a };
  return {};
}

/* ------------------------------------------------------------------ *
 * References and imports
 * ------------------------------------------------------------------ */

export function renderCilImports(p: CilProgram, page: HTMLElement): void {
  const info = p.referencesInfo();
  const perAssembly = new Map<string, number>();
  for (const m of p.imported) perAssembly.set(m.assembly, (perAssembly.get(m.assembly) ?? 0) + 1);
  const assemblies = info.assemblies.map(
    ([name, version, culture, key]) =>
      `<tr><td class="mono">${esc(name)}</td><td class="mono">${version}</td><td class="mono">${esc(culture || 'neutral')}</td><td class="mono">${esc(key)}</td><td class="mono" style="text-align:right">${n(perAssembly.get(name) ?? 0)}</td></tr>`,
  );
  const members = p.imported
    .map((m) => ({ m, uses: (m.field ? p.fieldRefs.get(m.addr)?.length : (p.callers.get(m.addr)?.length ?? 0) + (p.dataRefs.get(m.addr)?.length ?? 0)) ?? 0 }))
    .sort((a, b) => b.uses - a.uses || a.m.name.localeCompare(b.m.name));
  const LIMIT = 5000;
  const memberRows = members
    .slice(0, LIMIT)
    .map(({ m, uses }) => `<tr class="clickable" data-import="${m.addr}"><td class="mono">${esc(m.name)}</td><td class="mono">${esc(m.assembly)}</td><td>${esc(m.field ? t('inspector', 'field') : t('inspector', 'method'))}</td><td class="mono" style="text-align:right">${uses || ''}</td></tr>`)
    .join('');
  const pinvokes = p.pinvokes
    .map((pi) => {
      const fn = p.methodFunction(pi.method);
      return `<tr${fn ? ` class="clickable" data-goto="${fn.addr}"` : ''}><td class="mono">${esc(pi.name)}</td><td class="mono">${esc(pi.library)}</td><td class="mono">${esc(pi.entry)}</td><td class="mono" style="text-align:right">${p.callers.get(fn?.addr ?? -1)?.length ?? ''}</td></tr>`;
    })
    .join('');
  const forwarders = info.forwarders.map(([name, to]) => `<tr><td class="mono">${esc(name)}</td><td class="mono">${esc(to)}</td></tr>`);
  page.innerHTML = `
    <h2>${esc(t('imports', 'References and imports'))}</h2>
    <p class="lede">${esc(t('imports', 'The assemblies this one is built against, the members of theirs its code uses — methods and fields, through MemberRef tokens — and the functions of native libraries it calls through P/Invoke. Uses are counted in the code.'))}</p>
    <h3>${esc(tn('imports', '{count} referenced assembly', '{count} referenced assemblies', info.assemblies.length))}</h3>
    ${table([t('imports', 'Assembly'), t('imports', 'Version'), t('imports', 'Culture'), t('imports', 'Public key token'), t('imports', 'Members used')], assemblies.join(''))}
    ${pinvokes ? `<h3>${esc(tn('imports', '{count} P/Invoke', '{count} P/Invokes', p.pinvokes.length))}</h3>${table([t('imports', 'Method'), t('imports', 'Library'), t('imports', 'Entry point'), t('imports', 'Calls')], pinvokes)}` : ''}
    <h3>${esc(tn('imports', '{count} member of other assemblies', '{count} members of other assemblies', members.length))}</h3>
    ${table([t('imports', 'Name'), t('imports', 'Assembly'), t('imports', 'Kind'), t('imports', 'Uses')], memberRows, 'import-table')}
    ${members.length > LIMIT ? `<p class="hint">${esc(tn('inspector', 'and {count} more', 'and {count} more', members.length - LIMIT))}</p>` : ''}
    ${forwarders.length ? `<h3>${esc(tn('imports', '{count} type forwarded to another assembly', '{count} types forwarded to other assemblies', info.exported))}</h3>${table([t('imports', 'Type'), t('imports', 'Assembly')], forwarders.join(''))}` : ''}`;
}

/* ------------------------------------------------------------------ *
 * The Assembly page
 * ------------------------------------------------------------------ */

export function renderCilAssembly(p: CilProgram, page: HTMLElement): void {
  const pe = p.pe;
  const md = p.assemblyInfo();
  const flags = p.headerFlags;
  const entry = p.methodFunction(p.entryMethod);
  const [types, methods, fields, properties, events] = md.counts;
  const info: (string[] | null)[] = [
    [t('overview', 'File'), esc(`${state.fileName} · ${sizeLabel(state.fileSize)}`)],
    md.assembly ? [t('overview', 'Assembly'), esc(`${md.assembly[0]}, Version=${md.assembly[1]}, Culture=${md.assembly[2] || 'neutral'}`)] : [t('overview', 'Assembly'), esc(t('overview', 'none: a module of another assembly'))],
    [t('overview', 'Module'), esc(`${md.module[0]} · MVID ${md.module[1]}`)],
    [t('overview', 'Type'), esc(pe.dll ? t('overview', 'library (DLL)') : t('overview', 'executable'))],
    p.framework ? [t('overview', 'Target framework'), esc(p.framework)] : null,
    [t('overview', 'Runtime'), esc(`${md.runtime[0]} · ${t('overview', 'CLI header')} ${md.runtime[1]} · ${t('overview', 'metadata tables')} ${md.runtime[2]}`)],
    entry ? [t('overview', 'Entry point'), `<a href="#" data-goto="${entry.addr}">${esc(fnName(entry))}</a>`] : null,
    [t('overview', 'Flags'), esc(md.flags || '—')],
    [t('overview', 'Code'), esc(flags & 1 ? t('overview', 'IL only') : t('overview', 'IL and native code (mixed mode): only the IL is shown'))],
    p.readyToRun ? [t('overview', 'ReadyToRun'), esc(t('overview', 'compiled ahead of time as well: the native code beside the IL is not shown'))] : null,
    [t('overview', 'Strong name'), esc(md.strongName ? (flags & 8 ? t('overview', 'signed') : t('overview', 'space for a signature, not signed')) : t('overview', 'none'))],
    md.assembly?.[3] ? [t('overview', 'Public key'), `<span class="mono">${esc(md.assembly[3])}</span>`] : null,
    [t('overview', 'Container'), esc(`${pe.is64 ? 'PE32+' : 'PE32'} · ${pe.machineName} · ${pe.subsystemName}`)],
    [t('overview', 'Contents'), esc([tn('overview', '{count} type', '{count} types', Math.max(0, types - 1)), tn('overview', '{count} method', '{count} methods', methods), tn('overview', '{count} field', '{count} fields', fields), tn('overview', '{count} property', '{count} properties', properties), tn('overview', '{count} event', '{count} events', events)].join(', '))],
    md.warnings.length ? [t('overview', 'Problems'), esc(md.warnings.join('; '))] : null,
  ];
  const streams = md.streams.map(([name, offset, size]) => `<tr><td class="mono"><b>${esc(name)}</b></td><td class="mono">${hex(offset)}</td><td class="mono">${sizeLabel(size)}</td></tr>`).join('');
  const tables = md.tables.map(([id, name, rows]) => `<tr><td class="mono">0x${id.toString(16).padStart(2, '0')}</td><td class="mono">${esc(name)}</td><td class="mono" style="text-align:right">${n(rows)}</td></tr>`).join('');
  const resourceRows = md.resources.map(([name, isPublic, where]) => `<tr><td class="mono">${esc(name)}</td><td>${esc(isPublic ? 'public' : 'private')}</td><td class="mono">${esc(where ?? t('overview', 'in this file'))}</td></tr>`);
  const TYPE_LIMIT = 3000;
  const typeRows = md.types.map(
    ([name, kind, visibility, count, first]) =>
      `<tr${first !== null ? ` class="clickable" data-goto="${first}"` : ''}><td class="mono">${esc(name)}</td><td>${esc(kind)}</td><td>${esc(visibility)}</td><td class="mono" style="text-align:right">${count || ''}</td></tr>`,
  );
  page.innerHTML = `
    <h2>${esc(t('overview', '.NET assembly'))}</h2>
    <p class="lede">${esc(t('overview', 'What the file says about itself besides the code: its name and version, the runtime it was built for, the metadata streams and tables, the resources and the types.'))}</p>
    ${kv(info).replace('class="kv"', 'class="kv" style="max-width:900px"')}
    <h3>${esc(tn('overview', '{count} metadata stream', '{count} metadata streams', md.streams.length))}</h3>
    ${table([t('overview', 'Stream'), t('overview', 'File offset'), t('overview', 'Size')], streams)}
    <h3>${esc(t('overview', 'Metadata tables'))}</h3>
    ${table(['#', t('overview', 'Table'), t('overview', 'Rows')], tables)}
    ${resourceRows.length ? `<h3>${esc(tn('overview', '{count} resource', '{count} resources', md.resources.length))}</h3>${table([t('overview', 'Name'), t('overview', 'Visibility'), t('overview', 'Where')], resourceRows.join(''))}` : ''}
    <h3>${esc(tn('overview', '{count} type', '{count} types', Math.max(0, types - 1)))}</h3>
    ${table([t('overview', 'Type'), t('overview', 'Kind'), t('overview', 'Visibility'), t('overview', 'Methods')], typeRows.join(''))}
    ${types - 1 > TYPE_LIMIT ? `<p class="hint">${esc(tn('inspector', 'and {count} more', 'and {count} more', types - 1 - TYPE_LIMIT))}</p>` : ''}
  `;
}

