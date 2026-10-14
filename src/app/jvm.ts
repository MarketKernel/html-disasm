/**
 * The page's Java parts: the rows of the listing (bytecode as javap -c writes
 * it, each instruction at its pc, what a constant pool index names after
 * `//`, the protected ranges and handlers marked where they start), the
 * details panel for an instruction, a method, a label, a string or a member of
 * a class the program does not have, the Classes page — the JAR's manifest,
 * the classes, the module — and the references.
 *
 * Links are data attributes the page's click handlers follow: data-addr for
 * code or an import (its address), data-mem for a string, data-goto in lists,
 * data-import for an imported member, data-ref for the reference.
 */

import { JVM_CATALOGUE } from '../core/catalog';
import { classKind, constantComment, CONSTANT, escapeString, fieldType, javaName, javaRelease, methodTypes, modifiers, type ClassFile, type Handler } from '../core/jvm/classfile';
import { bytesText, insnText, JvmInsn, operandText, poolIndex } from '../core/jvm/decode';
import { headerParams, liftGroup } from '../core/jvm/hla';
import { F, OPERAND, opcodeText } from '../core/jvm/opcodes';
import { FIELD_BASE, IMPORT_BASE, STRING_BASE, type ImportedMember, type JvmProgram } from '../core/jvm/program';
import { parts } from '../core/wasm/hla';
import { n, t, tn } from '../core/i18n';
import { ROW, type Rows } from '../core/rows';
import { branchesTo, calledFromCard, calleeRef, callsCard, card, formsCard, goesToCard, hlaCard, insnDesc, insnHead, joinedNote, kv, labelInfoCard, mnemonicTip, refList, stringsCard, table, where, wordTip } from './cards';
import { sizeLabel } from './labels';
import { fnName, settings, state, type Selection } from './state';
import { esc, hex } from './ui';

const scratch = new JvmInsn();

/* ------------------------------------------------------------------ *
 * Instructions
 * ------------------------------------------------------------------ */

export function jvmClass(insn: JvmInsn): string {
  const op = insn.op;
  if (!op) return 'k-unknown';
  if (op.flags & F.CALL) return 'k-call';
  if (op.flags & (F.BRANCH | F.RETURN | F.THROW | F.END)) return 'k-branch';
  if (op.flags & (F.LOAD | F.STORE)) return 'k-mem';
  if (op.flags & F.COMPARE) return 'k-cmp';
  return '';
}

/** The address of a pc in the method an instruction is in. */
function pcAddr(p: JvmProgram, index: number, pc: number): number {
  const body = p.bodyOf(index);
  return body ? body.base + pc : -1;
}

function pcLink(p: JvmProgram, index: number, pc: number): string {
  return `<span class="t-name" data-addr="${pcAddr(p, index, pc)}">${pc}</span>`;
}

/** The name the class gives a local at an instruction (LocalVariableTable), for a comment. */
function localComment(p: JvmProgram, index: number, slot: number, pc: number, len: number): string {
  const body = p.bodyOf(index);
  if (!body) return '';
  const locals = p.classes[body.cls]!.localVariables(body.code).filter((v) => v.slot === slot);
  const v = locals.find((l) => pc >= l.start && pc < l.start + l.length) ?? locals.find((l) => pc + len >= l.start && pc + len <= l.start + l.length);
  return v ? `${v.name}: ${fieldType(v.descriptor)}` : '';
}

/** What a constant pool index names, as javap's comment, made into a link where it leads somewhere. */
function poolComment(p: JvmProgram, index: number, insn: JvmInsn): string {
  const body = p.bodyOf(index);
  if (!body) return '';
  const cf = p.classes[body.cls]!;
  const at = poolIndex(insn);
  const text = esc(constantComment(cf, at));
  const tag = cf.tags[at];
  if (tag === CONSTANT.Methodref || tag === CONSTANT.InterfaceMethodref || tag === CONSTANT.MethodHandle) {
    const callee = p.callee(body.cls, at);
    return callee ? `<span class="t-name" data-addr="${callee.addr}">${text}</span>` : `<span class="t-type">${text}</span>`;
  }
  if (tag === CONSTANT.String) return `<span class="t-string" data-mem="${p.stringAddr(cf.utf8(cf.ref1(at)))}">${text}</span>`;
  if (tag === CONSTANT.Fieldref) {
    const addr = p.fieldAddr(body.cls, at);
    return addr >= IMPORT_BASE ? `<span class="t-name" data-addr="${addr}">${text}</span>` : `<span class="t-type">${text}</span>`;
  }
  if (tag === CONSTANT.Integer || tag === CONSTANT.Long || tag === CONSTANT.Float || tag === CONSTANT.Double) return `<span class="t-imm">${text}</span>`;
  return `<span class="t-type">${text}</span>`;
}

/** An instruction with its operand made into links; `comments` collects what goes after it. */
export function jvmAsmHtml(p: JvmProgram, index: number, insn: JvmInsn, comments: string[]): string {
  const op = insn.op;
  const head = `<span class="r-mn ${jvmClass(insn)}" data-mn="${esc(insn.m)}" data-tip="${esc(mnemonicTip(insn.m, JVM_CATALOGUE.lookup(insn.m)))}">${esc(insn.m)}</span>`;
  const cf = p.classOf(index);
  if (!op) return `${head} <span class="t-imm">${esc(operandText(cf, insn).operand)}</span>`;
  const pad = (html: string) => `${head} <span class="r-ops">${html}</span>`;
  switch (op.operand) {
    case OPERAND.NONE: {
      const slot = /^[ilfda](?:load|store)_([0-3])$/.exec(insn.m);
      const name = slot ? localComment(p, index, Number(slot[1]), insn.at, insn.len) : '';
      if (name) comments.push(esc(name));
      return head;
    }
    case OPERAND.BRANCH16:
    case OPERAND.BRANCH32:
      return pad(pcLink(p, index, insn.a));
    case OPERAND.JSR16:
    case OPERAND.JSR32:
      // javap leaves the subroutine out; the comment says where it is.
      comments.push(`→ ${pcLink(p, index, insn.a)}`);
      return head;
    case OPERAND.TABLESWITCH:
    case OPERAND.LOOKUPSWITCH: {
      const keys = insn.keys ?? [];
      const headText = op.operand === OPERAND.TABLESWITCH ? `{ // ${keys[0] ?? 0} to ${keys.length ? keys[keys.length - 1] : -1}` : `{ // ${keys.length}`;
      const cases = keys.map((key, k) => `${key}: ${pcLink(p, index, insn.targets![k]!)}`);
      return pad(`${esc(headText)} ${[...cases, `default: ${pcLink(p, index, insn.a)}`, '}'].join(' ')}`);
    }
    case OPERAND.LOCAL:
    case OPERAND.LOCAL_W:
    case OPERAND.IINC:
    case OPERAND.IINC_W: {
      const name = localComment(p, index, insn.a, insn.at, insn.len);
      if (name) comments.push(esc(name));
      return pad(`<span class="t-reg">${esc(operandText(cf, insn).operand)}</span>`);
    }
    case OPERAND.CP8:
    case OPERAND.CP16:
    case OPERAND.INTERFACE:
    case OPERAND.DYNAMIC:
    case OPERAND.DIMENSIONS:
      comments.push(poolComment(p, index, insn));
      return pad(`<span class="t-imm">${esc(operandText(cf, insn).operand)}</span>`);
    case OPERAND.ATYPE:
      return pad(`<span class="t-type">${esc(operandText(cf, insn).operand)}</span>`);
  }
  const operand = operandText(cf, insn).operand;
  return operand ? pad(`<span class="t-imm">${esc(operand)}</span>`) : head;
}

/** An instruction's text as javap prints it. */
function plain(p: JvmProgram, index: number, insn: JvmInsn): string {
  return insnText(p.classOf(index), insn);
}

/* ------------------------------------------------------------------ *
 * HLA64 lines
 * ------------------------------------------------------------------ */

/** The words a line's plain text may hold, and the HLA64 word that explains each. */
const NEW_WORDS = new Map<string, string>([
  ['len', 'jvm-array'], ['new', 'jvm-new'], ['null', 'jvm-new'], ['_', 'jvm-pop'], ['this', 'jvm-local'], ['concat', 'jvm-concat'], ['lambda', 'jvm-lambda'],
]);
const CONVERSIONS = /^(?:[iu](?:8|16|32|64)|f32|f64)$/;
const KEYWORDS = new Set(['if', 'goto', 'return', 'switch', 'case', 'default', 'nan', 'inf']);
const TOKEN = /(\b(?:checkcast|instanceof|athrow|monitorenter|monitorexit|ldc|invokedynamic|[ld]cmp[lg]?|fcmp[lg]|[fd]rem)\b)(?=[<(])|(\b[A-Za-z_][A-Za-z0-9_]*\b)(?=\s*(\()?)|(-?\b(?:0x[0-9a-f]+|\d+(?:\.\d+)?(?:e[+-]?\d+)?)\b)/gi;

/** One token of a line's plain text, coloured. */
function tokenHtml(match: string, folded?: string, ident?: string, callParen?: string, number?: string): string {
  if (folded) return `<span class="t-new" data-tip="${wordTip('jvm-folded')}" data-mn="${esc(folded)}">${esc(folded)}</span>`;
  if (ident) {
    if (KEYWORDS.has(ident)) return `<span class="t-kw">${ident}</span>`;
    const id = NEW_WORDS.get(ident) ?? (callParen && CONVERSIONS.test(ident) ? 'jvm-convert' : undefined);
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

/** A field's declaration for a tooltip: `int hello.More.count`. */
function fieldTip(p: JvmProgram, addr: number): string {
  if (addr >= IMPORT_BASE) {
    const member = p.importByAddr.get(addr);
    return member ? member.full : '';
  }
  const field = p.fields[addr - FIELD_BASE];
  if (!field) return '';
  const mods = modifiers(field.access, 'field');
  return `${mods ? `${mods} ` : ''}${fieldType(field.descriptor)} ${javaName(p.classes[field.cls]!.name)}.${field.name}`;
}

/** An HLA64 line with its marks made into links and its words coloured. */
export function jvmMarkedHtml(p: JvmProgram, text: string): string {
  return parts(text)
    .map((part) => {
      switch (part.kind) {
        case 'f':
        case 'l':
          return part.value! >= 0 ? `<span class="t-name" data-addr="${part.value}">${esc(part.text)}</span>` : `<span class="t-type">${esc(part.text)}</span>`;
        case 's':
          return `<span class="t-string" data-mem="${part.value}">${esc(part.text)}</span>`;
        case 'v':
          return `<span class="t-reg">${esc(part.text)}</span>`;
        case 'g':
          return part.value! >= IMPORT_BASE ? `<span class="t-name" data-addr="${part.value}" data-tip="${esc(esc(fieldTip(p, part.value!)))}">${esc(part.text)}</span>` : `<span class="t-name" data-tip="${esc(esc(fieldTip(p, part.value!)))}">${esc(part.text)}</span>`;
      }
      return plainHtml(part.text);
    })
    .join('');
}

/** The HLA64 line of a row, or the instructions as they are when it has none. */
export function jvmHlaLine(p: JvmProgram, first: number, last: number): { html: string; words: string[]; raw: boolean; comments: string[] } {
  const line = liftGroup(p, first, last);
  if (line) return { html: jvmMarkedHtml(p, line.text), words: line.words, raw: false, comments: [] };
  // Instructions as they are keep what javap writes after them: `#116` says nothing on its own.
  const html: string[] = [];
  const comments: string[] = [];
  for (let i = first; i <= last; i++) html.push(jvmAsmHtml(p, i, p.insn(i), comments));
  return { html: html.join('<span class="t-op">; </span>'), words: ['instruction'], raw: true, comments };
}

/** `fn hello.Hello::sum(values: int[], count: int) -> long {`: the header of a method in the HLA64 view. */
function hlaHeader(p: JvmProgram, fnIndex: number): string {
  const fn = p.functions[fnIndex]!;
  const body = p.bodies[fnIndex]!;
  const params = headerParams(p, fnIndex).map(({ name, type }) => `${esc(name)}: <span class="t-type">${esc(type)}</span>`).join(', ');
  const ret = methodTypes(body.method.descriptor).ret.replace(/(?:[\w$]+\.)+/g, '');
  const name = fnName(fn);
  const shown = /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) ? name : `\`${name}\``;
  return `<span class="t-kw">fn</span> <span class="t-name" data-addr="${fn.addr}">${esc(shown)}</span>(${params})${ret !== 'void' ? ` -&gt; <span class="t-type">${esc(ret)}</span>` : ''} {`;
}

/* ------------------------------------------------------------------ *
 * Exception handling
 * ------------------------------------------------------------------ */

/** What a handler catches: a class, or anything (`any`, as javap writes it: a finally or a synchronized block). */
function catchText(cf: ClassFile, handler: Handler): string {
  return handler.catchType ? javaName(cf.className(handler.catchType)) : 'any';
}

/** A row of the exception table in words: `12 to 40 → 43 catch java.lang.NumberFormatException`. */
export function handlerText(cf: ClassFile, handler: Handler): string {
  return `${handler.start} to ${handler.end} → ${handler.handler} catch ${catchText(cf, handler)}`;
}

/** What starts at an instruction: `try`, `catch java.lang.Exception`. */
function regionText(p: JvmProgram, index: number): string {
  const cf = p.classOf(index);
  return (p.regions.get(index) ?? []).map(({ handler, part }) => (part === 'try' ? 'try' : `catch ${catchText(cf, handler)}`)).join(' · ');
}

/* ------------------------------------------------------------------ *
 * Rows
 * ------------------------------------------------------------------ */

function fnMeta(p: JvmProgram, fnIndex: number): string {
  const fn = p.functions[fnIndex]!;
  const callers = p.callers.get(fn.addr)?.length ?? 0;
  const kind = fn.kind === 'entry' ? t('fn', 'entry point') : fn.kind === 'export' ? t('fn', 'public') : '';
  return [tn('listing', '{count} instruction', '{count} instructions', fn.count), kind, callers ? tn('listing', '{count} caller', '{count} callers', callers) : ''].filter(Boolean).join(' · ');
}

export function jvmRowHtml(p: JvmProgram, rows: Rows, r: number, selected: boolean): string {
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
      const body = p.bodies[value]!;
      return `<div class="row fn${sel}" data-row="${r}"><span class="fn-title" title="${esc(fn.full)}">${esc(fnName(fn))}</span><span class="fn-meta">${esc(`${modifiers(body.method.access, 'method') || 'package'} ${body.method.descriptor} · ${fnMeta(p, value)}`)}</span></div>`;
    }
    case ROW.FN_END:
      return `<div class="row fn-end" data-row="${r}">}</div>`;
    case ROW.LABEL: {
      const regions = regionText(p, value);
      return `<div class="row label${sel}" data-row="${r}">L${p.pc(value)}:${regions ? `<span class="r-comment">// ${esc(regions)}</span>` : ''}</div>`;
    }
  }
  const insn = p.insn(value, scratch);
  const bytes = settings.bytes ? `<span class="r-bytes">${bytesText(p.classOf(value).bytes, p.fileOffset(value), insn.len, 5)}</span>` : '';
  const addr = `<span class="r-addr" title="${esc(`${hex(p.addrOf(value))} · ${t('listing', 'offset in the class file')} ${hex(p.fileOffset(value))}`)}">${p.pc(value)}</span>`;
  if (hla) {
    const last = p.joinedTo(value);
    const line = jvmHlaLine(p, value, last);
    return `<div class="row${sel}" data-row="${r}">${addr}${bytes}<span class="r-indent"></span><span class="r-code">${line.html}</span>${line.comments.length ? `<span class="r-comment">// ${line.comments.join(' ')}</span>` : ''}</div>`;
  }
  const comments: string[] = [];
  const code = jvmAsmHtml(p, value, insn, comments);
  return `<div class="row${sel}" data-row="${r}">${addr}${bytes}<span class="r-code">${code}</span>${comments.length ? `<span class="r-comment">// ${comments.join(' ')}</span>` : ''}</div>`;
}

/* ------------------------------------------------------------------ *
 * Details panel
 * ------------------------------------------------------------------ */

/** `hello.Hello::main L12`: a place in a method is its pc. */
const pcText = (pc: number) => `L${pc}`;


const POOL_KINDS: Record<number, string> = { 1: 'Utf8', 3: 'Integer', 4: 'Float', 5: 'Long', 6: 'Double', 7: 'Class', 8: 'String', 9: 'Fieldref', 10: 'Methodref', 11: 'InterfaceMethodref', 12: 'NameAndType', 15: 'MethodHandle', 16: 'MethodType', 17: 'Dynamic', 18: 'InvokeDynamic', 19: 'Module', 20: 'Package' };

function instructionCard(p: JvmProgram, index: number): string {
  const insn = p.insn(index, new JvmInsn());
  const entry = JVM_CATALOGUE.lookup(insn.m);
  const body = p.bodyOf(index);
  const cf = p.classOf(index);
  const addr = p.addrOf(index);
  const head = insnHead(insn.m, jvmClass(insn), entry, insn.op ? '' : t('inspector', 'Not an instruction the decoder knows'));
  const desc = insnDesc(entry, t('inspector', 'This byte is not a JVM opcode, or its operands run past the end of the method: the class file is damaged, or this is not bytecode.'));
  const op = insn.op;
  const pool = poolIndex(insn);
  const rows = kv([
    entry?.stack ? [t('inspector', 'Stack'), esc(entry.stack)] : null,
    entry?.operation ? [t('inspector', 'Does'), esc(entry.operation)] : null,
    pool ? [t('inspector', 'Constant'), `#${pool} <span class="hint">${esc(POOL_KINDS[cf.tags[pool] ?? 0] ?? '?')}</span>`] : null,
    [t('inspector', 'Offset'), `pc ${p.pc(index)} · ${hex(addr)} · ${t('inspector', 'class file')} ${hex(p.fileOffset(index))}`],
    [t('inspector', 'In'), where(p, addr, pcText)],
    op ? [t('inspector', 'Opcode'), esc(opcodeText(op.code))] : null,
    [t('inspector', 'Encoding'), esc(bytesText(cf.bytes, p.fileOffset(index), insn.len, 24))],
  ]);
  let html = `<section class="card">${head}<div class="insn-text">${esc(plain(p, index, insn))}</div>${desc}${rows}</section>`;

  // HLA64
  const [first, last] = p.joined(index);
  const hla = jvmHlaLine(p, first, last);
  html += hlaCard(hla.html, hla.raw ? '' : joinedNote(last - first + 1), hla.words);
  html += goesToCard(p, [...new Set(p.branchTargets(index))]);
  if (body && pool && op && (op.flags & F.CALL || cf.tags[pool] === CONSTANT.MethodHandle)) {
    if (op.operand === OPERAND.DYNAMIC) {
      const site = cf.dynamic(pool);
      const bootstrap = cf.bootstrapMethods()[site.bootstrap];
      const args = (bootstrap?.args ?? []).map((arg) => {
        const target = cf.tags[arg] === CONSTANT.MethodHandle ? p.callee(body.cls, arg) : undefined;
        return target ? calleeRef(target, '→') : `<div class="syntax">${esc(constantComment(cf, arg))}</div>`;
      });
      html += card(t('inspector', 'Call site'), `<p class="hint">${esc(t('inspector', 'What this call does is decided when it first runs, by the bootstrap method, which is given the constants below.'))}</p><div class="syntax">${esc(bootstrap ? constantComment(cf, bootstrap.method) : '?')}</div>${args.join('')}`);
    } else {
      const callee = p.callee(body.cls, pool);
      const title = op.flags & F.CALL ? t('inspector', 'Calls') : t('inspector', 'Refers to');
      const outside = callee?.kind === 'import' ? `<p class="hint">${esc(t('inspector', 'A member of a class this program does not have: {owner}', { owner: javaName((callee as ImportedMember).owner) }))}</p>` : '';
      html += card(title, `${callee ? `<div class="reflist">${calleeRef(callee, callee.kind === 'import' ? 'ref' : callee.addr.toString(16))}</div>` : ''}<p class="hint mono">${esc(constantComment(cf, pool))}</p>${outside}`);
    }
  }
  if (body && pool && cf.tags[pool] === CONSTANT.String) html += stringCard(p, p.stringAddr(cf.utf8(cf.ref1(pool))));
  if (body && pool && cf.tags[pool] === CONSTANT.Fieldref) {
    const field = p.fieldAddr(body.cls, pool);
    const refs = p.fieldRefs.get(field) ?? [];
    html += card(t('inspector', 'Field'), `<p class="hint mono">${esc(fieldTip(p, field))}</p><h3 style="margin-top:12px">${esc(tn('inspector', 'Used in {count} place', 'Used in {count} places', refs.length))}</h3>${refList(p, refs, pcText)}`);
  }
  // The protected ranges and handlers it is in.
  const pc = p.pc(index);
  const handlers = p.handlersOf(index).filter((h) => (pc >= h.start && pc < h.end) || pc === h.handler);
  if (handlers.length) {
    html += card(t('inspector', 'Exception handling'), `<p class="hint">${esc(t('inspector', 'The protected ranges this instruction is in, and the handlers it starts.'))}</p>${handlers.map((h) => `<div class="syntax">${esc(handlerText(cf, h))}</div>`).join('')}`);
  }
  if (entry) html += formsCard(entry.forms, (form) => ({ url: form.url, label: 'JVMS ↗' }), insn.m, p.counts.find((c) => c.mnemonic === insn.m)?.count ?? 0, Infinity);
  return html;
}

function stringCard(p: JvmProgram, addr: number): string {
  const text = p.stringAt.get(addr)?.text ?? '';
  const refs = p.dataRefs.get(addr) ?? [];
  const body =
    `<div class="pre">${esc(text)}</div>` +
    kv([
      [t('inspector', 'Length'), tn('inspector', '{count} character', '{count} characters', text.length)],
      [t('inspector', 'As javap writes it'), `<span class="mono">${esc(escapeString(text))}</span>`],
    ]) +
    `<h3 style="margin-top:12px">${esc(tn('inspector', '{count} reference', '{count} references', refs.length))}</h3>${refList(p, refs, pcText)}`;
  return card(t('inspector', 'String'), body);
}

function fnCard(p: JvmProgram, fnIndex: number): string {
  const fn = p.functions[fnIndex]!;
  const body = p.bodies[fnIndex]!;
  const cf = p.classes[body.cls]!;
  const method = body.method;
  const locals = cf.localVariables(body.code);
  const lines = cf.lineNumbers(body.code);
  const thrown = cf.exceptions(method);
  const signature = cf.signature(method.attributes);
  const source = cf.sourceFile();
  const rows = kv([
    [t('inspector', 'Name'), esc(fnName(fn))],
    [t('inspector', 'Declaration'), `<span class="mono">${esc(fn.full)}</span>`],
    [t('inspector', 'Descriptor'), `<span class="mono">${esc(method.descriptor)}</span>`],
    signature ? [t('inspector', 'Generic signature'), `<span class="mono">${esc(signature)}</span>`] : null,
    thrown.length ? [t('inspector', 'Throws'), `<span class="mono">${esc(thrown.map(javaName).join(', '))}</span>`] : null,
    [t('inspector', 'Kind'), esc(fn.kind === 'entry' ? t('fn', 'entry point') : fn.kind === 'export' ? t('fn', 'public') : t('fn', 'named'))],
    [t('inspector', 'Access flags'), `<span class="mono">0x${method.access.toString(16).padStart(4, '0')}</span>`],
    [t('inspector', 'Class'), `${esc(javaName(cf.name))}${cf.path ? ` <span class="hint">${esc(cf.path)}</span>` : ''}`],
    source ? [t('inspector', 'Source'), esc(`${source}${lines.length ? `:${Math.min(...lines.map(([, line]) => line))}` : ''}`)] : null,
    [t('inspector', 'Size'), `${tn('inspector', '{count} instruction', '{count} instructions', fn.count)} · ${tn('inspector', '{count} byte', '{count} bytes', body.code.length)}`],
    [t('inspector', 'Frame'), esc(`max_stack ${body.code.maxStack} · max_locals ${body.code.maxLocals}`)],
    locals.length ? [t('inspector', 'Locals'), `<div class="mono">${locals.slice(0, 200).map((v) => esc(`${v.slot}: ${v.name} ${fieldType(v.descriptor)} (${v.start}–${v.start + v.length})`)).join('<br>')}${locals.length > 200 ? '<br>…' : ''}</div>`] : null,
  ]);
  let html = card(t('inspector', 'Method'), rows);
  if (body.code.handlers.length) {
    html += card(tn('inspector', '{count} exception handler', '{count} exception handlers', body.code.handlers.length), body.code.handlers.map((h) => `<div class="syntax">${esc(handlerText(cf, h))}</div>`).join(''));
  }
  const callers = p.callers.get(fn.addr) ?? [];
  html += calledFromCard(p, callers, pcText);
  const taken = p.dataRefs.get(fn.addr) ?? [];
  if (taken.length) html += card(t('inspector', 'Taken as a lambda or method reference'), refList(p, taken, pcText));
  // Calls and strings, from its instructions.
  const calls = new Map<number, number>();
  const strings = new Map<number, string>();
  let dynamic = 0;
  const insn = new JvmInsn();
  for (let i = fn.first; i < fn.first + Math.min(fn.count, 50000); i++) {
    p.insn(i, insn);
    if (!insn.op) continue;
    const pool = poolIndex(insn);
    if (insn.op.flags & F.CALL && insn.op.operand !== OPERAND.DYNAMIC) {
      const callee = p.callee(body.cls, pool);
      if (callee) calls.set(callee.addr, (calls.get(callee.addr) ?? 0) + 1);
    } else if (insn.op.flags & F.CALL) dynamic++;
    if (pool && cf.tags[pool] === CONSTANT.String) {
      const text = cf.utf8(cf.ref1(pool));
      strings.set(p.stringAddr(text), text);
    }
  }
  const callList = [...calls].sort((a, b) => b[1] - a[1]);
  const lookupFn = (addr: number) => p.importByAddr.get(addr) ?? p.functionAt(addr);
  const callRows = callList.map(([addr, count]) => {
    const callee = lookupFn(addr);
    return callee ? calleeRef(callee, `${count}×`) : '';
  });
  html += callsCard(callList.length, callRows, dynamic ? tn('inspector', 'and {count} invokedynamic call site', 'and {count} invokedynamic call sites', dynamic) : '');
  html += stringsCard(strings, { base: STRING_BASE });
  return html;
}

function labelCard(p: JvmProgram, index: number): string {
  const cf = p.classOf(index);
  const regions = (p.regions.get(index) ?? []).map(({ handler }) => `<div class="syntax">${esc(handlerText(cf, handler))}</div>`).join('');
  const what = regions ? `<p class="insn-desc">${esc(t('inspector', 'A protected range or a handler starts here.'))}</p>${regions}` : '';
  return labelInfoCard(p, p.addrOf(index), what, branchesTo(p, index), pcText) + instructionCard(p, index);
}

function importCard(p: JvmProgram, addr: number | undefined): string {
  const member = addr === undefined ? undefined : p.importByAddr.get(addr);
  if (!member) return card(t('inspector', 'Imported function'), '');
  const used = member.field ? p.fieldRefs.get(member.addr) ?? [] : [...(p.callers.get(member.addr) ?? []), ...(p.dataRefs.get(member.addr) ?? [])].sort((a, b) => a - b);
  const rows = kv([
    [t('inspector', 'Name'), esc(fnName(member))],
    [t('inspector', 'Declaration'), `<span class="mono">${esc(member.full)}</span>`],
    [t('inspector', 'Descriptor'), `<span class="mono">${esc(member.descriptor)}</span>`],
    [t('inspector', 'Class'), esc(javaName(member.owner))],
    [t('inspector', 'Package'), esc(member.package || '—')],
    [t('inspector', 'Kind'), esc(member.field ? t('inspector', 'field') : t('inspector', 'method'))],
  ]);
  return card(t('inspector', 'Member of another class'), rows) + card(tn('inspector', 'Used in {count} place', 'Used in {count} places', used.length), refList(p, used, pcText));
}

/** The details panel for whatever is selected in Java bytecode. */
export function jvmInspector(p: JvmProgram, sel: NonNullable<Selection>): string {
  switch (sel.kind) {
    case 'insn':
      return instructionCard(p, sel.index);
    case 'fn':
      return fnCard(p, sel.fn);
    case 'label':
      return labelCard(p, sel.index);
    case 'string':
      return p.stringAt.has(sel.addr) ? stringCard(p, sel.addr) : card(t('inspector', 'Data'), `<p class="hint">${hex(sel.addr)}</p>`);
    case 'import':
      return importCard(p, sel.addr);
  }
}

/** Where Enter goes from an instruction: a branch target, a called method, a string. */
export function jvmFollow(p: JvmProgram, index: number): { code?: number; mem?: number; import?: ImportedMember } {
  const [target] = p.branchTargets(index);
  if (target !== undefined) return { code: p.addrOf(target) };
  const insn = p.insn(index);
  const body = p.bodyOf(index);
  const pool = poolIndex(insn);
  if (!body || !pool) return {};
  const cf = p.classes[body.cls]!;
  const tag = cf.tags[pool];
  if (tag === CONSTANT.Methodref || tag === CONSTANT.InterfaceMethodref || tag === CONSTANT.MethodHandle) {
    const callee = p.callee(body.cls, pool);
    if (callee?.kind === 'import') return { import: callee as ImportedMember };
    if (callee) return { code: callee.addr };
  }
  if (tag === CONSTANT.Fieldref) {
    const member = p.importByAddr.get(p.fieldAddr(body.cls, pool));
    if (member) return { import: member };
  }
  if (tag === CONSTANT.String) return { mem: p.stringAddr(cf.utf8(cf.ref1(pool))) };
  return {};
}

/* ------------------------------------------------------------------ *
 * References
 * ------------------------------------------------------------------ */

function uses(p: JvmProgram, m: ImportedMember): number {
  return m.field ? p.fieldRefs.get(m.addr)?.length ?? 0 : (p.callers.get(m.addr)?.length ?? 0) + (p.dataRefs.get(m.addr)?.length ?? 0);
}

export function renderJvmImports(p: JvmProgram, page: HTMLElement): void {
  // Packages and classes outside the program, with the members of theirs the code uses.
  const byPackage = new Map<string, { classes: Set<string>; members: number; uses: number }>();
  for (const m of p.imported) {
    const entry = byPackage.get(m.package) ?? { classes: new Set(), members: 0, uses: 0 };
    entry.classes.add(m.owner);
    entry.members++;
    entry.uses += uses(p, m);
    byPackage.set(m.package, entry);
  }
  const packages = [...byPackage].sort((a, b) => b[1].uses - a[1].uses || a[0].localeCompare(b[0]));
  const packageRows = packages.map(([name, e]) => `<tr><td class="mono">${esc(name || t('imports', '(the unnamed package)'))}</td><td class="mono" style="text-align:right">${n(e.classes.size)}</td><td class="mono" style="text-align:right">${n(e.members)}</td><td class="mono" style="text-align:right">${n(e.uses)}</td></tr>`).join('');
  const members = p.imported.map((m) => ({ m, uses: uses(p, m) })).sort((a, b) => b.uses - a.uses || a.m.name.localeCompare(b.m.name));
  const LIMIT = 5000;
  const memberRows = members
    .slice(0, LIMIT)
    .map(({ m, uses: count }) => `<tr class="clickable" data-import="${m.addr}"><td class="mono">${esc(m.name)}</td><td>${esc(m.field ? t('inspector', 'field') : t('inspector', 'method'))}</td><td class="mono" style="text-align:right">${count || ''}</td><td class="mono">${esc(m.descriptor)}</td></tr>`)
    .join('');
  const classes = new Set(p.imported.map((m) => m.owner));
  page.innerHTML = `
    <h2>${esc(t('imports', 'References'))}</h2>
    <p class="lede">${esc(t('imports', 'The classes this code uses that it does not have — of the Java class library, or of other libraries it is run with — and the methods and fields of theirs it calls and reads, by package. Uses are counted in the code.'))}</p>
    <h3>${esc(tn('imports', '{count} package', '{count} packages', packages.length))}</h3>
    ${table([t('imports', 'Package'), t('imports', 'Classes'), t('imports', 'Members used'), t('imports', 'Uses')], packageRows)}
    <h3>${esc(tn('imports', '{count} member of {classes} other classes', '{count} members of {classes} other classes', members.length, { classes: n(classes.size) }))}</h3>
    ${table([t('imports', 'Name'), t('imports', 'Kind'), t('imports', 'Uses'), t('imports', 'Descriptor')], memberRows, 'import-table')}
    ${members.length > LIMIT ? `<p class="hint">${esc(tn('inspector', 'and {count} more', 'and {count} more', members.length - LIMIT))}</p>` : ''}`;
}

/* ------------------------------------------------------------------ *
 * The Classes page
 * ------------------------------------------------------------------ */

const KIND_NAMES = (kind: ReturnType<typeof classKind>): string => kind;

export function renderJvmArchive(p: JvmProgram, page: HTMLElement): void {
  const c = p.container;
  const versions = new Map<number, number>();
  for (const cf of p.classes) versions.set(cf.major, (versions.get(cf.major) ?? 0) + 1);
  const kinds = new Map<string, number>();
  for (const cf of p.classes) kinds.set(classKind(cf), (kinds.get(classKind(cf)) ?? 0) + 1);
  const packages = new Set(p.classes.map((cf) => cf.name.slice(0, Math.max(0, cf.name.lastIndexOf('/')))));
  const module = p.classes.find((cf) => cf.access & 0x8000)?.module();
  const single = c.kind === 'class' ? p.classes[0] : undefined;
  const info: (string[] | null)[] = [
    [t('overview', 'File'), esc(`${state.fileName} · ${sizeLabel(state.fileSize)}`)],
    [t('overview', 'Type'), esc(c.kind === 'class' ? t('overview', 'class file') : c.kind === 'jmod' ? t('overview', 'Java module (.jmod)') : c.from ? t('overview', 'Android library (AAR): its classes.jar') : t('overview', 'Java archive (JAR)'))],
    [t('overview', 'Class file versions'), esc([...versions].sort((a, b) => b[0] - a[0]).map(([major, count]) => `${major} (Java ${javaRelease(major)})${versions.size > 1 ? ` × ${n(count)}` : ''}`).join(', '))],
    p.kotlin ? [t('overview', 'Language'), esc(t('overview', 'Kotlin (classes carry kotlin.Metadata)'))] : null,
    [t('overview', 'Contents'), esc([tn('overview', '{count} class', '{count} classes', p.classes.length), tn('overview', '{count} package', '{count} packages', packages.size), tn('overview', '{count} method with code', '{count} methods with code', p.functions.length), tn('overview', '{count} field', '{count} fields', p.fields.length)].join(', '))],
    [t('overview', 'Kinds'), esc([...kinds].map(([kind, count]) => `${KIND_NAMES(kind as ReturnType<typeof classKind>)} ${n(count)}`).join(', '))],
    p.entry ? [t('overview', 'Entry point'), `<a href="#" data-goto="${p.entry.addr}">${esc(fnName(p.entry))}</a>`] : null,
    module ? [t('overview', 'Module'), esc(`${module.name}${module.version ? `@${module.version}` : ''}`)] : null,
    c.versioned ? [t('overview', 'Other releases'), esc(tn('overview', '{count} class for other Java releases (META-INF/versions) is not shown', '{count} classes for other Java releases (META-INF/versions) are not shown', c.versioned))] : null,
    c.broken.length ? [t('overview', 'Problems'), esc(c.broken.slice(0, 20).map((b) => `${b.name}: ${b.reason}`).join('; '))] : null,
  ];
  if (single) {
    const source = single.sourceFile();
    info.push(
      [t('overview', 'Class'), `<span class="mono">${esc(`${modifiers(single.access, 'class')} ${classKind(single)} ${javaName(single.name)}`.trim())}</span>`],
      single.superClass ? [t('overview', 'Extends'), `<span class="mono">${esc(javaName(single.className(single.superClass)))}</span>`] : null,
      single.interfaces.length ? [t('overview', 'Implements'), `<span class="mono">${esc(single.interfaces.map((i) => javaName(single.className(i))).join(', '))}</span>`] : null,
      source ? [t('overview', 'Source'), esc(source)] : null,
      [t('overview', 'Constant pool'), esc(tn('overview', '{count} entry', '{count} entries', single.tags.length - 1))],
      [t('overview', 'Attributes'), `<span class="mono">${esc(single.attributes.map((a) => a.name).join(', ') || '—')}</span>`],
    );
  }
  const manifest = [...c.manifest].map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td class="mono">${esc(v)}</td></tr>`).join('');
  const LIMIT = 3000;
  const methodsOf = new Map<number, number>();
  const firstOf = new Map<number, number>();
  p.bodies.forEach((b, k) => {
    methodsOf.set(b.cls, (methodsOf.get(b.cls) ?? 0) + 1);
    if (!firstOf.has(b.cls)) firstOf.set(b.cls, p.functions[k]!.addr);
  });
  const classRows = p.classes
    .slice(0, LIMIT)
    .map((cf, k) => {
      const first = firstOf.get(k);
      return `<tr${first !== undefined ? ` class="clickable" data-goto="${first}"` : ''}><td class="mono">${esc(javaName(cf.name))}</td><td>${esc(classKind(cf))}</td><td>${esc(modifiers(cf.access, 'class') || 'package')}</td><td class="mono">${cf.major}</td><td class="mono" style="text-align:right">${methodsOf.get(k) ?? ''}</td><td class="mono">${esc(cf.sourceFile() ?? '')}</td></tr>`;
    })
    .join('');
  const resources = c.resources.slice(0, 2000).map((r) => `<tr><td class="mono">${esc(r.name)}</td><td class="mono" style="text-align:right">${sizeLabel(r.size)}</td></tr>`).join('');
  const moduleRows = module
    ? [
        [t('overview', 'Requires'), module.requires],
        [t('overview', 'Exports'), module.exports],
        [t('overview', 'Opens'), module.opens],
        [t('overview', 'Uses'), module.uses],
        [t('overview', 'Provides'), module.provides],
      ]
        .filter(([, list]) => (list as string[]).length)
        .map(([k, list]) => `<tr><td>${esc(k as string)}</td><td class="mono">${esc((list as string[]).join(', '))}</td></tr>`)
        .join('')
    : '';
  page.innerHTML = `
    <h2>${esc(c.kind === 'class' ? t('overview', 'Java class') : t('overview', 'Java archive'))}</h2>
    <p class="lede">${esc(t('overview', 'What the file says about itself besides the code: its manifest, the class file versions, the module, the classes and the other files it carries.'))}</p>
    ${kv(info).replace('class="kv"', 'class="kv" style="max-width:900px"')}
    ${manifest ? `<h3>${esc(t('overview', 'Manifest'))}</h3>${table([t('overview', 'Attribute'), t('overview', 'Value')], manifest)}` : ''}
    ${moduleRows ? `<h3>${esc(t('overview', 'Module'))}</h3>${table([t('overview', 'Directive'), t('overview', 'Modules and packages')], moduleRows)}` : ''}
    <h3>${esc(tn('overview', '{count} class', '{count} classes', p.classes.length))}</h3>
    ${table([t('overview', 'Class'), t('overview', 'Kind'), t('overview', 'Access'), t('overview', 'Version'), t('overview', 'Methods'), t('overview', 'Source')], classRows)}
    ${p.classes.length > LIMIT ? `<p class="hint">${esc(tn('inspector', 'and {count} more', 'and {count} more', p.classes.length - LIMIT))}</p>` : ''}
    ${resources ? `<h3>${esc(tn('overview', '{count} other file', '{count} other files', c.resources.length))}</h3>${table([t('overview', 'Name'), t('overview', 'Size')], resources)}` : ''}
  `;
}
