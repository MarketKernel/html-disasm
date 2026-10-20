/** Small DOM helpers shared by the page's modules. */

export const $ = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`#${id} is missing`);
  return element as T;
};

const ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const esc = (text: string): string => text.replace(/[&<>"']/g, (c) => ESCAPES[c]!);

export const hex = (value: number): string => `0x${value.toString(16)}`;

/** A long text in a comment, cut short. */
export const clip = (text: string) => (text.length > 120 ? `${text.slice(0, 120)}…` : text);

/** The address column of a listing row. */
export const addrCell = (addr: number) => `<span class="r-addr">${addr.toString(16)}</span>`;

/** Creates an element: h('div', { class: 'x', onclick }, 'text', child). */
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, unknown> = {},
  ...children: (Node | string | null | undefined | false)[]
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (name.startsWith('on') && typeof value === 'function') element.addEventListener(name.slice(2), value as EventListener);
    else if (name === 'html') element.innerHTML = String(value);
    else element.setAttribute(name, value === true ? '' : String(value));
  }
  for (const child of children) if (child !== null && child !== undefined && child !== false) element.append(child);
  return element;
}

let toastTimer = 0;
export function toast(text: string): void {
  const element = $('toast');
  element.textContent = text;
  element.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    element.hidden = true;
  }, 2600);
}

/** A tooltip that follows the pointer over elements with data-tip (HTML, already escaped). */
export function installTooltips(root: HTMLElement): void {
  const tip = $('tooltip');
  let current: HTMLElement | null = null;
  root.addEventListener('pointerover', (event) => {
    const target = (event.target as HTMLElement).closest<HTMLElement>('[data-tip]');
    if (!target || target === current) return;
    current = target;
    tip.innerHTML = target.dataset.tip ?? '';
    tip.hidden = false;
    place(event);
  });
  root.addEventListener('pointermove', (event) => {
    if (current) place(event);
  });
  root.addEventListener('pointerout', (event) => {
    const next = (event.relatedTarget as HTMLElement | null)?.closest?.('[data-tip]');
    if (next === current) return;
    current = null;
    tip.hidden = true;
  });
  const place = (event: PointerEvent) => {
    const { innerWidth, innerHeight } = window;
    const rect = tip.getBoundingClientRect();
    let x = event.clientX + 14;
    let y = event.clientY + 16;
    if (x + rect.width > innerWidth - 8) x = innerWidth - rect.width - 8;
    if (y + rect.height > innerHeight - 8) y = event.clientY - rect.height - 10;
    tip.style.left = `${Math.max(8, x)}px`;
    tip.style.top = `${Math.max(8, y)}px`;
  };
}

export const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

/** A virtual list: only the rows on screen exist in the DOM. */
export class VirtualList<T> {
  private inner: HTMLDivElement;
  private items: T[] = [];
  private frame = 0;
  current = -1;

  constructor(
    private readonly host: HTMLElement,
    private readonly rowHeight: number,
    private readonly render: (item: T, index: number) => string,
    private readonly onPick: (item: T, index: number, event: MouseEvent) => void,
  ) {
    this.inner = h('div', { class: 'vlist-inner' });
    host.replaceChildren(this.inner);
    host.addEventListener('scroll', () => this.schedule());
    host.addEventListener('click', (event) => {
      const row = (event.target as HTMLElement).closest<HTMLElement>('.vrow');
      if (!row) return;
      const index = Number(row.dataset.index);
      const item = this.items[index];
      if (item !== undefined) this.onPick(item, index, event);
    });
    new ResizeObserver(() => this.schedule()).observe(host);
  }

  set(items: T[]): void {
    this.items = items;
    this.inner.style.height = `${items.length * this.rowHeight}px`;
    this.schedule();
  }

  get length(): number {
    return this.items.length;
  }

  reveal(index: number): void {
    const top = index * this.rowHeight;
    if (top < this.host.scrollTop || top + this.rowHeight > this.host.scrollTop + this.host.clientHeight) {
      this.host.scrollTop = Math.max(0, top - this.host.clientHeight / 3);
    }
    this.schedule();
  }

  refresh(): void {
    this.schedule();
  }

  private schedule(): void {
    if (this.frame) return;
    this.frame = requestAnimationFrame(() => {
      this.frame = 0;
      this.draw();
    });
  }

  private draw(): void {
    const first = Math.max(0, Math.floor(this.host.scrollTop / this.rowHeight) - 4);
    const last = Math.min(this.items.length, Math.ceil((this.host.scrollTop + this.host.clientHeight) / this.rowHeight) + 4);
    let html = '';
    for (let i = first; i < last; i++) {
      html += `<div class="vrow${i === this.current ? ' is-current' : ''}" data-index="${i}" style="top:${i * this.rowHeight}px">${this.render(this.items[i]!, i)}</div>`;
    }
    this.inner.innerHTML = html;
  }
}
