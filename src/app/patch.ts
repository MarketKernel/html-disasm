/**
 * Changing instructions of a macOS program and downloading the result.
 *
 * A selected instruction opens a small window: the new instruction is typed
 * as assembly (`mov w0, #1`, `b.ne 0x…`, `nop`) or as its bytes in hex, or
 * picked from the few changes that fit it — the opposite condition, an
 * unconditional branch, "do nothing", "return". Whatever is typed is decoded
 * and shown before it is applied, so what goes into the file is exactly what
 * the preview says, and never a word that decodes to something else.
 *
 * A change is written into the opened file at once; the listing marks the
 * rows, and every change can be undone. The file is downloaded signed again
 * ad hoc (src/core/patch.ts), so Apple Silicon still runs it.
 */

import { decode } from '../core/arm64/decode';
import { formatInsn, type Insn } from '../core/arm64/types';
import { t, tn } from '../core/i18n';
import { applyPatch, CannotSign, fileOffsetOf, resignFile, type Patch } from '../core/patch';
import { parseMachO, type MachO } from '../core/macho';
import type { Program } from '../core/program';
import { fnName, nativeProgram, state } from './state';
import { $, esc, hex, toast } from './ui';

/** An assembler of one line to a 32-bit word, wired in once it is loaded. */
export type Assembler = (text: string, pc: number, resolve?: (name: string) => number | undefined) => { word: number } | { error: string };
let assembler: Assembler | null = null;
export function setAssembler(fn: Assembler): void {
  assembler = fn;
}

/** Changes by the address of the first instruction each replaces. */
const patches = new Map<number, Patch>();
/** Every instruction index a change covers, for marking the rows. */
const covered = new Set<number>();
let goTo: (addr: number) => void = () => {};
let editing = -1;

const program = () => nativeProgram() as Program;
const image = (): MachO => program().image.macho!;

/** Whether the open program can be changed here: an arm64 Mach-O file with the bytes still at hand. */
export function canPatch(): boolean {
  const p = state.program;
  return !!p && p.arch === 'arm64' && !!state.fileBytes && !!(p as Program).image.macho;
}

export function isPatched(index: number): boolean {
  return covered.has(index);
}

export function patchCount(): number {
  return patches.size;
}

/** Forgets the changes of the program that was open before. */
export function resetPatches(): void {
  patches.clear();
  covered.clear();
  updateBar();
}

const toWord = (b: Uint8Array, at: number) => (b[at]! | (b[at + 1]! << 8) | (b[at + 2]! << 16) | (b[at + 3]! << 24)) >>> 0;
const bytesOf = (words: number[]) => {
  const out = new Uint8Array(words.length * 4);
  new DataView(out.buffer);
  words.forEach((w, i) => {
    out[i * 4] = w & 0xff;
    out[i * 4 + 1] = (w >>> 8) & 0xff;
    out[i * 4 + 2] = (w >>> 16) & 0xff;
    out[i * 4 + 3] = (w >>> 24) & 0xff;
  });
  return out;
};

/** The word at an instruction index, as the file holds it now (a change included). */
function currentWord(index: number): number {
  const p = program();
  const offset = fileOffsetOf(image(), p.addrOf(index), 4);
  return offset !== undefined && state.fileBytes ? toWord(state.fileBytes, offset) : p.words[index]!;
}

/* ------------------------------------------------------------------ *
 * The edit window
 * ------------------------------------------------------------------ */

export function initPatch(navigate: (addr: number) => void): void {
  goTo = navigate;
  $('editor-input').addEventListener('input', preview);
  $('editor-input').addEventListener('keydown', (event) => {
    if ((event as KeyboardEvent).key === 'Enter') apply();
  });
  $('editor-cancel').addEventListener('click', close);
  $('editor-apply').addEventListener('click', apply);
  $('editor').addEventListener('mousedown', (event) => {
    if (event.target === $('editor')) close();
  });
  $('editor-quick').addEventListener('click', (event) => {
    const chip = (event.target as HTMLElement).closest<HTMLElement>('[data-fill]');
    if (!chip) return;
    const input = $<HTMLInputElement>('editor-input');
    input.value = chip.dataset.fill!;
    input.focus();
    preview();
  });
  $('patch-download').addEventListener('click', () => void download());
  $('patch-reset').addEventListener('click', undoAll);
}

export function openEditor(index: number): void {
  if (!canPatch()) return;
  editing = index;
  const p = program();
  const insn = decode(currentWord(index), p.addrOf(index));
  $('editor-addr').textContent = hex(p.addrOf(index));
  $('editor-before').textContent = formatInsn(insn);
  const input = $<HTMLInputElement>('editor-input');
  input.value = '';
  $('editor-quick').innerHTML = quickChanges(index, insn)
    .map((q) => `<button type="button" class="chip" data-fill="${esc(q.text)}">${esc(q.label)}</button>`)
    .join('');
  $('editor').hidden = false;
  preview();
  input.focus();
}

function close(): void {
  $('editor').hidden = true;
  editing = -1;
}

/** What the input would do: the decoded instructions, or why it cannot be used. */
function parseInput(text: string, pc: number): { words: number[] } | { error: string } {
  const trimmed = text.trim();
  if (!trimmed) return { words: [] };
  // Hex: whole words (8 digits each), spaces and a leading 0x allowed, as the Encoding line shows
  // them. Nothing but hex digits here, so a mnemonic (which has letters beyond a-f or is not 8
  // digits long) never looks like hex.
  const hexText = trimmed.replace(/0x/gi, '').replace(/\s+/g, '');
  if (/^[0-9a-f]+$/i.test(hexText) && hexText.length >= 8 && hexText.length % 8 === 0) {
    const words: number[] = [];
    for (let i = 0; i < hexText.length; i += 8) words.push(parseInt(hexText.slice(i, i + 8), 16) >>> 0);
    return { words };
  }
  const lines = trimmed.split(/[;\n]/).map((s) => s.trim()).filter(Boolean);
  if (!assembler) return { error: t('editor', 'Enter the bytes in hex.') };
  const words: number[] = [];
  for (let i = 0; i < lines.length; i++) {
    const result = assembler(lines[i]!, pc + i * 4, nameResolver());
    if ('error' in result) return { error: lines.length > 1 ? `${lines[i]}: ${result.error}` : result.error };
    words.push(result.word);
  }
  return { words };
}

/** Names the input may use as a branch or adr target: functions, labels, imports. */
function nameResolver(): (name: string) => number | undefined {
  const p = program();
  return (name) => {
    const fn = p.functions.find((f) => fnName(f) === name || f.full === name || f.raw === name);
    if (fn) return fn.addr;
    const label = /^L([0-9a-f]+)$/.exec(name);
    return label ? parseInt(label[1]!, 16) : undefined;
  };
}

function preview(): void {
  const host = $('editor-preview');
  const apply = $<HTMLButtonElement>('editor-apply');
  if (editing < 0) return;
  const p = program();
  const pc = p.addrOf(editing);
  const parsed = parseInput($<HTMLInputElement>('editor-input').value, pc);
  if ('error' in parsed) {
    host.innerHTML = `<span class="editor-bad">${esc(parsed.error)}</span>`;
    apply.disabled = true;
    return;
  }
  if (!parsed.words.length) {
    host.textContent = '';
    apply.disabled = true;
    return;
  }
  const room = roomBytes(editing);
  if (parsed.words.length * 4 > room) {
    host.innerHTML = `<span class="editor-bad">${esc(tn('editor', 'There is room for {count} instruction here.', 'There is room for {count} instructions here.', room / 4))}</span>`;
    apply.disabled = true;
    return;
  }
  // The preview is the bytes decoded back, so it is exactly what the file will hold.
  host.innerHTML = parsed.words
    .map((w, i) => `<div class="editor-line"><span class="mono editor-word">${w.toString(16).padStart(8, '0')}</span> <span class="mono">${esc(formatInsn(decode(w, pc + i * 4)))}</span></div>`)
    .join('');
  apply.disabled = false;
}

/** How many bytes a change at an index may fill: to the end of the instruction's code section. */
function roomBytes(index: number): number {
  const p = program();
  const range = p.rangeOfIndex(index);
  return range ? (range.first + range.count - index) * 4 : 4;
}

function apply(): void {
  if (editing < 0) return;
  const p = program();
  const pc = p.addrOf(editing);
  const parsed = parseInput($<HTMLInputElement>('editor-input').value, pc);
  if ('error' in parsed || !parsed.words.length || parsed.words.length * 4 > roomBytes(editing)) return;
  const after = bytesOf(parsed.words);
  const offset = fileOffsetOf(image(), pc, after.length);
  if (offset === undefined || !state.fileBytes) {
    toast(t('editor', 'These bytes are not in the file and cannot be changed.'));
    return;
  }
  const before = state.fileBytes.slice(offset, offset + after.length);
  const patch: Patch = { addr: pc, offset, before, after };
  // A change over the same bytes replaces the one there; its own original bytes are kept.
  const existing = patches.get(pc);
  if (existing) patch.before = existing.before.length >= after.length ? existing.before.slice(0, after.length) : patch.before;
  applyPatch(state.fileBytes, patch);
  patches.set(pc, patch);
  syncWords(patch);
  remark();
  close();
  updateBar();
  state.rows.clear();
  goTo(pc);
}

/** Writes a change's words into the analysis arrays, so the listing decodes the new instructions. */
function syncWords(patch: Patch): void {
  const p = program();
  const first = p.indexOf(patch.addr);
  for (let k = 0; k < patch.after.length / 4; k++) p.words[first + k] = toWord(patch.after, k * 4);
}

/** Rebuilds the set of covered instruction indices from the patches. */
function remark(): void {
  covered.clear();
  const p = program();
  for (const patch of patches.values()) {
    const first = p.indexOf(patch.addr);
    for (let k = 0; k < patch.after.length / 4; k++) covered.add(first + k);
  }
}

function undoAll(): void {
  if (!state.fileBytes) return;
  const p = program();
  const where = [...patches.keys()][0] ?? p.addrOf(0);
  for (const patch of patches.values()) {
    applyPatch(state.fileBytes, patch, true);
    const first = p.indexOf(patch.addr);
    for (let k = 0; k < patch.before.length / 4; k++) p.words[first + k] = toWord(patch.before, k * 4);
  }
  patches.clear();
  covered.clear();
  updateBar();
  state.rows.clear();
  goTo(where);
}

export function updateBar(): void {
  const bar = $('patch-bar');
  bar.hidden = patches.size === 0;
  $('patch-count').textContent = tn('patch', '{count} change', '{count} changes', patches.size);
}

/* ------------------------------------------------------------------ *
 * Quick changes
 * ------------------------------------------------------------------ */

const NOP = 0xd503201f;
const RET = 0xd65f03c0;
const movzW0 = (imm: number) => (0x52800000 | ((imm & 0xffff) << 5)) >>> 0;
const asHex = (...words: number[]) => words.map((w) => (w >>> 0).toString(16).padStart(8, '0')).join(' ');

/**
 * The changes offered as one-click fills, each already the word(s) in hex so
 * they work without the assembler. A conditional branch can be inverted (its
 * condition bits flipped, the target kept) or made to always branch; cbz/cbnz
 * and tbz/tbnz toggle their test bit; anything can become nop, ret, or a
 * function that returns 0 or 1.
 */
function quickChanges(index: number, insn: Insn): { label: string; text: string }[] {
  const out: { label: string; text: string }[] = [];
  const pc = program().addrOf(index);
  const word = currentWord(index);
  if (patches.has(pc)) out.push({ label: t('editor', 'Revert'), text: asHex(toWord(patches.get(pc)!.before, 0)) });
  if (/^b\.?c?\.[a-z]{2}$/.test(insn.m)) {
    // b.cond and bc.cond keep the condition in the low 4 bits; the opposite is that xor 1.
    out.push({ label: t('editor', 'Opposite condition'), text: asHex(((word & ~0xf) | ((word & 0xf) ^ 1)) >>> 0) });
    if (insn.target !== undefined) out.push({ label: t('editor', 'Always branch'), text: asHex((0x14000000 | (((insn.target - pc) >> 2) & 0x03ffffff)) >>> 0) });
  }
  if (/^(cbz|cbnz|tbz|tbnz)$/.test(insn.m)) out.push({ label: t('editor', 'Opposite test'), text: asHex((word ^ (1 << 24)) >>> 0) });
  out.push({ label: 'nop', text: asHex(NOP) });
  out.push({ label: 'ret', text: asHex(RET) });
  out.push({ label: t('editor', 'Return 1'), text: asHex(movzW0(1), RET) });
  out.push({ label: t('editor', 'Return 0'), text: asHex(movzW0(0), RET) });
  return out;
}

/* ------------------------------------------------------------------ *
 * Download
 * ------------------------------------------------------------------ */

async function download(): Promise<void> {
  if (!state.fileBytes || !patches.size) return;
  const copy = state.fileBytes.slice();
  let signed: Awaited<ReturnType<typeof resignFile>> | undefined;
  try {
    signed = await resignFile(copy, parseMachO(copy));
  } catch (err) {
    if (!(err instanceof CannotSign)) {
      toast(t('editor', 'The file could not be signed again: {reason}', { reason: err instanceof Error ? err.message : String(err) }));
      return;
    }
    // No signature to rewrite: the file is still downloaded as it is.
  }
  const name = state.fileName.replace(/(\.[^./]+)?$/, (ext) => `-patched${ext}`);
  const blob = new Blob([copy as Uint8Array<ArrayBuffer>], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  if (signed?.was === 'developer') toast(t('editor', 'Downloaded, signed ad hoc. It no longer carries its developer signature or notarization; macOS may ask to confirm it on first run.'));
  else if (signed) toast(t('editor', 'Downloaded, signed ad hoc so it will run.'));
  else toast(t('editor', 'Downloaded.'));
}
