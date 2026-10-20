/**
 * The listing: millions of rows in a scroll box.
 *
 * Browsers cap an element's height at a few tens of millions of pixels, and
 * a big program has more rows than that at 22 px each. So the scroll box
 * holds a spacer of at most MAX_SPACER pixels, its scrollbar position maps to
 * a row, and the wheel and the keys move a fractional "top row" directly —
 * scrolling stays smooth however big the program is. Only the rows on screen
 * are in the DOM.
 *
 * In the left margin, arrows show the branches inside the function on
 * screen; those that touch the selected instruction are drawn stronger.
 */

import type { Disassembly } from '../core/disassembly';
import { t } from '../core/i18n';
import { IF } from '../core/program';
import { ROW, type Rows } from '../core/rows';
import { rowHtml } from './render';
import { armProgram, emit, fnName, on, program, rowsFor, select, settings, state } from './state';
import { viewOf } from './views';
import { $, esc, hex, toast } from './ui';

const ROW_H = 22;
const MAX_SPACER = 4_000_000;
const ARROW_SCAN = 900;

export class Listing {
  private readonly box = $('listing');
  private readonly spacer = $('listing-spacer');
  private readonly window = $('listing-window');
  private readonly rowsHost = $('listing-rows');
  private readonly arrows = document.getElementById('arrows') as unknown as SVGSVGElement;
  private rows!: Rows;
  /** The program the rows are of. */
  private shownFor: Disassembly | null = null;
  private top = 0;
  private selectedRow = -1;
  private expectedScroll = -1;
  private frame = 0;
  private targets = new Map<number, number[]>();

  constructor() {
    this.box.addEventListener('wheel', (event) => this.onWheel(event), { passive: false });
    this.box.addEventListener('scroll', () => this.onScroll());
    this.box.addEventListener('click', (event) => this.onClick(event));
    this.box.addEventListener('dblclick', (event) => {
      if ((event.target as HTMLElement).closest('[data-addr], [data-mem]')) return;
      this.follow();
    });
    this.box.addEventListener('keydown', (event) => this.onKey(event));
    new ResizeObserver(() => {
      this.layout();
      this.draw();
    }).observe(this.box);
    on('settings', () => {
      this.box.classList.toggle('no-arrows', !settings.arrows);
      this.draw();
    });
    on('select', () => this.draw());
  }

  /** Shows a program's rows in the current mode, keeping the instruction at the top in view. */
  show(rows: Rows): void {
    // Another mode of the same program keeps the place; another program starts afresh.
    const same = !!this.rows && this.shownFor === program();
    const anchor = same ? this.instructionAt(Math.floor(this.top)) : -1;
    const selected = same && this.selectedRow >= 0 ? this.instructionAt(this.selectedRow) : -1;
    this.rows = rows;
    this.shownFor = program();
    this.targets.clear();
    this.box.classList.toggle('no-arrows', !settings.arrows);
    this.layout();
    if (anchor >= 0) this.top = Math.max(0, rows.rowOfInsn[anchor]! - 0);
    if (selected >= 0) this.selectedRow = rows.rowOfInsn[selected]!;
    else this.selectedRow = -1;
    this.clamp();
    this.syncScroll();
    this.draw();
  }

  get current(): Rows {
    return this.rows;
  }

  focus(): void {
    this.box.focus({ preventScroll: true });
  }

  private visibleRows(): number {
    return Math.max(1, this.box.clientHeight / ROW_H);
  }

  private maxTop(): number {
    return Math.max(0, this.rows.count - this.visibleRows() + 2);
  }

  private spacerHeight(): number {
    return Math.min(this.rows.count * ROW_H + 2 * ROW_H, MAX_SPACER);
  }

  private layout(): void {
    if (!this.rows) return;
    this.spacer.style.height = `${this.spacerHeight()}px`;
  }

  private clamp(): void {
    this.top = Math.min(Math.max(0, this.top), this.maxTop());
  }

  private scrollRange(): number {
    return Math.max(1, this.spacerHeight() - this.box.clientHeight);
  }

  private syncScroll(): void {
    const max = this.maxTop();
    const position = max ? (this.top / max) * this.scrollRange() : 0;
    this.expectedScroll = Math.round(position);
    this.box.scrollTop = position;
  }

  private onScroll(): void {
    if (!this.rows) return;
    if (this.expectedScroll >= 0 && Math.abs(this.box.scrollTop - this.expectedScroll) <= 1) {
      this.expectedScroll = -1;
      this.draw();
      return;
    }
    this.expectedScroll = -1;
    this.top = (this.box.scrollTop / this.scrollRange()) * this.maxTop();
    this.clamp();
    this.draw();
  }

  private onWheel(event: WheelEvent): void {
    if (!this.rows || event.ctrlKey) return;
    event.preventDefault();
    const unit = event.deltaMode === 1 ? 1 : event.deltaMode === 2 ? this.visibleRows() : 1 / ROW_H;
    this.top += event.deltaY * unit;
    this.clamp();
    this.syncScroll();
    this.draw();
  }

  draw(): void {
    if (this.frame || !this.rows) return;
    this.frame = requestAnimationFrame(() => {
      this.frame = 0;
      this.paint();
    });
  }

  private paint(): void {
    const first = Math.floor(this.top);
    const offset = (this.top - first) * ROW_H;
    const count = Math.ceil(this.visibleRows()) + 2;
    this.window.style.transform = `translateY(${this.box.scrollTop - offset}px)`;
    let html = '';
    const last = Math.min(this.rows.count, first + count);
    for (let r = first; r < last; r++) html += rowHtml(this.rows, r, r === this.selectedRow);
    this.rowsHost.innerHTML = html;
    if (settings.arrows) this.paintArrows(first, last);
    else this.arrows.innerHTML = '';
    // The breadcrumb names where the selection is, or, with none on screen, the top third.
    const anchor = this.selectedRow >= first && this.selectedRow < last ? this.selectedRow : first + Math.floor(this.visibleRows() / 3);
    this.updateCrumb(Math.min(anchor, this.rows.count - 1));
  }

  private instructionAt(row: number): number {
    const rows = this.rows;
    for (let r = Math.max(0, row); r < Math.min(rows.count, row + 4); r++) {
      const kind = rows.kind[r]!;
      if (kind === ROW.INSN || kind === ROW.LABEL || kind === ROW.PAD) return rows.value[r]!;
      if (kind === ROW.FN_HEADER || kind === ROW.GAP) return program().functions[rows.value[r]!]!.first;
    }
    return -1;
  }

  private updateCrumb(row: number): void {
    const p = program();
    const index = this.instructionAt(row);
    const crumb = $('crumb');
    if (index < 0) {
      crumb.textContent = '';
      return;
    }
    const fn = p.functions[p.functionOfIndex(index)];
    const addr = p.addrOf(index);
    crumb.innerHTML = fn
      ? `<b>${esc(fnName(fn))}</b>${addr > fn.addr ? ` <span class="mono">+${(addr - fn.addr).toString(16)}</span>` : ''}`
      : `<span class="mono">${hex(addr)}</span>`;
    crumb.title = fn ? fn.full : '';
  }

  /* -------------------------- arrows -------------------------- */

  private targetsOf(index: number): number[] {
    let targets = this.targets.get(index);
    if (targets === undefined) {
      targets = [...new Set(program().branchTargets(index))];
      this.targets.set(index, targets);
    }
    return targets;
  }

  private paintArrows(firstRow: number, lastRow: number): void {
    const p = program();
    const rows = this.rows;
    let lo = Infinity;
    let hi = -Infinity;
    for (let r = firstRow; r < lastRow; r++) {
      const kind = rows.kind[r]!;
      if (kind === ROW.INSN || kind === ROW.LABEL) {
        lo = Math.min(lo, rows.value[r]!);
        hi = Math.max(hi, rows.value[r]!);
      }
    }
    if (lo === Infinity) {
      this.arrows.innerHTML = '';
      return;
    }
    const selectedInsn = this.selectedRow >= 0 && rows.kind[this.selectedRow] === ROW.INSN ? rows.value[this.selectedRow]! : -1;
    const edges: { from: number; to: number; a: number; b: number; lane: number; hot: boolean }[] = [];
    const start = Math.max(0, lo - ARROW_SCAN);
    const end = Math.min(p.totalInstructions, hi + ARROW_SCAN);
    for (let i = start; i < end; i++) {
      if (!(p.flags[i]! & IF.BRANCH)) continue;
      for (const to of this.targetsOf(i)) {
        if (to < 0 || to === i) continue;
        const a = Math.min(i, to);
        const b = Math.max(i, to);
        if (b < lo || a > hi) continue;
        if (p.functionOfIndex(i) !== p.functionOfIndex(to)) continue;
        const hot = selectedInsn >= 0 && (selectedInsn === i || selectedInsn === to || rows.rowOfInsn[i] === rows.rowOfInsn[selectedInsn]);
        edges.push({ from: i, to, a, b, lane: 0, hot });
        if (edges.length > 400) break;
      }
    }
    edges.sort((x, y) => x.b - x.a - (y.b - y.a));
    const lanes: [number, number][][] = [];
    for (const edge of edges) {
      let lane = 0;
      while (lane < 7 && lanes[lane]?.some(([a, b]) => !(edge.b < a || edge.a > b))) lane++;
      (lanes[lane] ??= []).push([edge.a, edge.b]);
      edge.lane = lane;
    }
    const rowY = (index: number, target: boolean) => {
      let row = rows.rowOfInsn[index]!;
      if (target && row > 0 && rows.kind[row - 1] === ROW.LABEL) row--;
      const y = (row - firstRow) * ROW_H + ROW_H / 2;
      return Math.max(-ROW_H, Math.min(y, (lastRow - firstRow + 1) * ROW_H));
    };
    let paths = '';
    let heads = '';
    const ordered = edges.sort((x, y) => Number(x.hot) - Number(y.hot));
    for (const edge of ordered) {
      const x = 40 - edge.lane * 5;
      const y1 = rowY(edge.from, false);
      const y2 = rowY(edge.to, true);
      const cls = `${edge.to < edge.from ? 'up' : ''}${edge.hot ? ' hot' : ''}`;
      paths += `<path class="${cls}" d="M46 ${y1}H${x}V${y2}H45"/>`;
      if (y2 > -ROW_H && y2 < (lastRow - firstRow) * ROW_H) heads += `<polygon class="${edge.hot ? 'hot' : ''}" points="46,${y2} 41,${y2 - 3.5} 41,${y2 + 3.5}"/>`;
    }
    this.arrows.setAttribute('height', String((lastRow - firstRow + 1) * ROW_H));
    this.arrows.innerHTML = paths + heads;
  }

  /* -------------------------- selection & navigation -------------------------- */

  selectRow(row: number, flash = false): void {
    const rows = this.rows;
    if (row < 0 || row >= rows.count) return;
    this.selectedRow = row;
    const kind = rows.kind[row]!;
    const value = rows.value[row]!;
    if (kind === ROW.INSN || kind === ROW.PAD) select({ kind: 'insn', index: value });
    else if (kind === ROW.LABEL) select({ kind: 'label', index: value });
    else if (kind === ROW.FN_HEADER || kind === ROW.FN_END) select({ kind: 'fn', fn: value });
    else select(null);
    if (flash) {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => this.rowsHost.querySelector(`[data-row="${row}"]`)?.classList.add('is-flash'));
      });
    }
  }

  private ensureVisible(row: number): void {
    const visible = this.visibleRows();
    if (row < this.top + 1) this.top = row - 1;
    else if (row > this.top + visible - 2) this.top = row - visible + 2;
    this.clamp();
    this.syncScroll();
    this.draw();
  }

  scrollTo(row: number): void {
    this.top = row - Math.floor(this.visibleRows() / 3);
    this.clamp();
    this.syncScroll();
    this.draw();
  }

  /** The address the view is at, for the history. */
  here(): number {
    const p = program();
    const index = this.selectedRow >= 0 ? this.instructionAt(this.selectedRow) : this.instructionAt(Math.floor(this.top));
    return index >= 0 ? p.addrOf(index) : -1;
  }

  /** Goes to an address in code: its function header if it starts one, else the instruction. */
  goTo(addr: number, record = true): boolean {
    const p = program();
    const index = p.indexOf(addr);
    if (index < 0) {
      toast(t('listing', 'That address is not in code'));
      return false;
    }
    if (record) {
      const here = this.here();
      if (here >= 0 && here !== addr) {
        state.history.push(here);
        if (state.history.length > 200) state.history.shift();
        state.future = [];
      }
    }
    const rows = this.rows;
    let row = rows.rowOfInsn[index]!;
    const fnStart = p.flags[index]! & IF.FUNCTION;
    this.scrollTo(fnStart ? row - 2 : row);
    if (fnStart) row = row - 1;
    this.selectRow(row, true);
    emit('navigate');
    return true;
  }

  back(): void {
    const addr = state.history.pop();
    if (addr === undefined) return;
    const here = this.here();
    if (here >= 0) state.future.push(here);
    this.goTo(addr, false);
  }

  forward(): void {
    const addr = state.future.pop();
    if (addr === undefined) return;
    const here = this.here();
    if (here >= 0) state.history.push(here);
    this.goTo(addr, false);
  }

  /** Follows the selected instruction: its branch or call target, or the data it points at. */
  follow(): void {
    const sel = state.selection;
    if (!sel || sel.kind !== 'insn') return;
    const open = program();
    const own = viewOf(open).follow;
    if (own) {
      const to = own(sel.index);
      if (to.code !== undefined) this.goTo(to.code);
      else if (to.import) select({ kind: 'import', name: to.import.raw ?? to.import.name, addr: to.import.addr });
      else if (to.mem !== undefined) select({ kind: 'string', addr: to.mem });
      return;
    }
    const p = armProgram();
    const insn = p.insn(sel.index);
    let target = insn.target;
    if (insn.m === 'adrp' && sel.index + 1 < p.totalInstructions) {
      const next = this.rowsHost.querySelector<HTMLElement>(`[data-row="${this.selectedRow}"] [data-addr]`);
      if (next) target = Number(next.dataset.addr);
    }
    if (target === undefined) {
      const link = this.rowsHost.querySelector<HTMLElement>(`[data-row="${this.selectedRow}"] [data-addr]`);
      if (link) target = Number(link.dataset.addr);
    }
    if (target === undefined) return;
    if (p.indexOf(target) >= 0) this.goTo(target);
    else if (p.stringAt.has(target) || p.dataAt(target)) select({ kind: 'string', addr: target });
  }

  private onClick(event: MouseEvent): void {
    const target = event.target as HTMLElement;
    const link = target.closest<HTMLElement>('[data-addr]');
    const mem = target.closest<HTMLElement>('[data-mem]');
    const rowEl = target.closest<HTMLElement>('[data-row]');
    if (rowEl) this.selectRow(Number(rowEl.dataset.row));
    if (mem) select({ kind: 'string', addr: Number(mem.dataset.mem) });
    else if (link) {
      const addr = Number(link.dataset.addr);
      const p = program();
      const imported = viewOf(p).importAt(addr);
      if (p.indexOf(addr) >= 0) this.goTo(addr);
      else if (imported) select({ kind: 'import', name: imported.raw ?? imported.name, addr });
      else select({ kind: 'string', addr });
    }
    this.focus();
  }

  private onKey(event: KeyboardEvent): void {
    if (!this.rows) return;
    const page = Math.floor(this.visibleRows()) - 2;
    const move = (delta: number) => {
      let row = this.selectedRow < 0 ? Math.floor(this.top) : this.selectedRow + delta;
      row = Math.max(0, Math.min(this.rows.count - 1, row));
      while (this.rows.kind[row] === ROW.GAP && row + Math.sign(delta || 1) >= 0 && row + Math.sign(delta || 1) < this.rows.count) row += Math.sign(delta || 1);
      this.selectRow(row);
      this.ensureVisible(row);
    };
    switch (event.key) {
      case 'ArrowDown':
        move(1);
        break;
      case 'ArrowUp':
        move(-1);
        break;
      case 'PageDown':
        move(page);
        break;
      case 'PageUp':
        move(-page);
        break;
      case 'Home':
        move(-this.rows.count);
        break;
      case 'End':
        move(this.rows.count);
        break;
      case 'Enter':
        this.follow();
        break;
      default:
        return;
    }
    event.preventDefault();
  }
}

/** Opens the listing in a mode, building its rows the first time. */
export function rowsForMode(mode: 'asm' | 'hla'): Rows {
  return rowsFor(mode);
}
