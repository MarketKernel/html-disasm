/**
 * What the page knows at any moment: the program, the listing mode, the
 * selection, the navigation history and the settings. Modules talk through
 * the small event hub at the bottom rather than calling each other.
 */

import { catalogueFor, type Catalogue } from '../core/catalog';
import type { Disassembly, Fn } from '../core/disassembly';
import type { LiftContext } from '../core/hla';
import type { Arm32Program } from '../core/arm32/program';
import type { Bundle } from '../core/bundle';
import type { Program } from '../core/program';
import { buildRows, type Mode, type Rows } from '../core/rows';
import type { WasmProgram } from '../core/wasm/program';
import type { X86Program } from '../core/x86/program';

export type Theme = 'system' | 'light' | 'dark';
export type Names = 'short' | 'full' | 'raw';
/** The interface language: the browser's, or one picked in the settings. */
export type LanguageSetting = 'system' | 'en' | 'ru';

export interface Settings {
  language: LanguageSetting;
  theme: Theme;
  names: Names;
  mode: Mode;
  bytes: boolean;
  arrows: boolean;
  inspector: boolean;
  /** Widths of the side panels in pixels, as the person dragged them. */
  sidebarWidth: number;
  inspectorWidth: number;
}

export const PANEL_WIDTHS = { sidebarWidth: 290, inspectorWidth: 370 } as const;
const DEFAULTS: Settings = { language: 'system', theme: 'system', names: 'short', mode: 'asm', bytes: false, arrows: true, inspector: true, ...PANEL_WIDTHS };
const KEY = 'arm64-disassembler.settings';

const width = (value: unknown, fallback: number): number => (typeof value === 'number' && Number.isFinite(value) && value >= 120 && value <= 4000 ? Math.round(value) : fallback);

/** Settings from localStorage, each field checked: anything unknown falls back to its default. */
function readSettings(): Settings {
  let stored: Record<string, unknown> = {};
  try {
    stored = JSON.parse(localStorage.getItem(KEY) ?? '{}') ?? {};
  } catch {
    stored = {};
  }
  const pick = <T>(value: unknown, allowed: readonly T[], fallback: T): T => (allowed.includes(value as T) ? (value as T) : fallback);
  return {
    language: pick(stored.language, ['system', 'en', 'ru'] as const, DEFAULTS.language),
    theme: pick(stored.theme, ['system', 'light', 'dark'] as const, DEFAULTS.theme),
    names: pick(stored.names, ['short', 'full', 'raw'] as const, DEFAULTS.names),
    mode: pick(stored.mode, ['asm', 'hla'] as const, DEFAULTS.mode),
    bytes: typeof stored.bytes === 'boolean' ? stored.bytes : DEFAULTS.bytes,
    arrows: typeof stored.arrows === 'boolean' ? stored.arrows : DEFAULTS.arrows,
    inspector: typeof stored.inspector === 'boolean' ? stored.inspector : DEFAULTS.inspector,
    sidebarWidth: width(stored.sidebarWidth, DEFAULTS.sidebarWidth),
    inspectorWidth: width(stored.inspectorWidth, DEFAULTS.inspectorWidth),
  };
}

export const settings: Settings = readSettings();

export function saveSettings(change: Partial<Settings>): void {
  Object.assign(settings, change);
  try {
    localStorage.setItem(KEY, JSON.stringify(settings));
  } catch {
    // Private windows may refuse storage; the settings still hold for this visit.
  }
  emit('settings');
}

/** What is selected: an instruction (by index), a function header, or a label. */
export type Selection =
  | { kind: 'insn'; index: number }
  | { kind: 'fn'; fn: number }
  | { kind: 'label'; index: number }
  | { kind: 'string'; addr: number }
  | { kind: 'import'; name: string; addr?: number }
  | null;

export const state = {
  program: null as Disassembly | null,
  fileName: '',
  fileSize: 0,
  rows: new Map<Mode, Rows>(),
  selection: null as Selection,
  history: [] as number[],
  future: [] as number[],
  context: null as LiftContext | null,
  /** The whole file as it was opened, for patching; the program reads a slice of it. */
  fileBytes: null as Uint8Array | null,
  /** The bundle the program came from, when it was taken out of an app archive (.ipa). */
  bundle: undefined as Bundle | undefined,
};

export function program(): Disassembly {
  if (!state.program) throw new Error('no program open');
  return state.program;
}

/** The open program as an arm64 Mach-O, for the parts of the page that are about one. */
export function armProgram(): Program {
  const p = program();
  if (p.arch !== 'arm64') throw new Error('not an arm64 program');
  return p as Program;
}

export function isWasm(p: Disassembly | null): p is WasmProgram {
  return p?.arch === 'wasm';
}

/** A program the HLA64 view cannot show: HLA64 has no target for 32-bit Arm or 32-bit x86. */
export function noHla(p: Disassembly | null): boolean {
  return p?.arch === 'arm32' || (p?.arch === 'x86' && (p as X86Program).mode === 32);
}

/**
 * Where an import's code is called from: through its stub, or through its slot — `call qword ptr
 * [rip + …]` on x86, a register loaded from the slot on Arm (`blr x8`, as MSVC calls imports).
 */
export function importCallers(p: Program | Arm32Program | X86Program, name: string, stub?: number): number[] {
  const out = stub !== undefined ? [...(p.callers.get(stub) ?? [])] : [];
  for (const [slot, imported] of p.importSlots) if (imported === name) out.push(...(p.slotCallers.get(slot) ?? []));
  return out.sort((a, b) => a - b);
}

/** The open program as a native one (arm64, 32-bit Arm, x86), with its Mach-O, ELF or PE image. */
export function nativeProgram(): Program | Arm32Program | X86Program {
  const p = program();
  if (p.arch === 'wasm' || p.arch === 'cil' || p.arch === 'jvm') throw new Error('not a native program');
  return p as Program | Arm32Program | X86Program;
}

/** The listing mode the open program can show. */
export function modeFor(mode: Mode): Mode {
  return noHla(state.program) ? 'asm' : mode;
}

/** The instructions of the open program's architecture (arm64 before one is open). */
export function catalogue(): Catalogue {
  return catalogueFor(state.program?.arch ?? 'arm64');
}

export function rowsFor(wanted: Mode): Rows {
  const mode = modeFor(wanted);
  let rows = state.rows.get(mode);
  if (!rows) {
    rows = buildRows(program(), mode);
    state.rows.set(mode, rows);
  }
  return rows;
}

/** The name a function goes by, as the settings ask. */
export function fnName(fn: Fn): string {
  if (settings.names === 'raw' && fn.raw) return fn.raw;
  if (settings.names === 'full') return fn.full;
  return fn.name;
}

/** The lifting context, naming functions as the settings ask. */
export function context(): LiftContext {
  if (!state.context) {
    const base = armProgram().context();
    state.context = {
      ...base,
      target: (addr) => {
        const found = base.target(addr);
        if (found && found.kind !== 'label') {
          const fn = armProgram().functionAt(addr);
          if (fn) return { ...found, name: fnName(fn) };
        }
        return found;
      },
    };
  }
  return state.context;
}

type Event = 'select' | 'navigate' | 'settings' | 'mode' | 'open' | 'view' | 'language' | 'patch';
const handlers = new Map<Event, Set<() => void>>();

export function on(event: Event, handler: () => void): void {
  if (!handlers.has(event)) handlers.set(event, new Set());
  handlers.get(event)!.add(handler);
}

export function emit(event: Event): void {
  for (const handler of handlers.get(event) ?? []) handler();
}

export function select(selection: Selection): void {
  state.selection = selection;
  emit('select');
}
