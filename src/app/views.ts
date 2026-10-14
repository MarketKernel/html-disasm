/**
 * What differs in the page from one kind of program to another, in one table:
 * the title and the tabs, the rows of the listing, the details panel, where
 * Enter goes, the members of other modules, the Imports and overview pages,
 * where the program opens, what the statistics count. The rest of the page
 * asks the view of the open program instead of asking which kind it is.
 *
 * Native code (arm64, 32-bit Arm, x86) shares the Imports page, the overview
 * of its Mach-O, ELF or PE file and its imports, which pages.ts draws; arm64,
 * the first architecture, draws its rows (render.ts), its details panel
 * (inspector.ts) and follows its instructions (listing.ts) where those are,
 * so its view leaves them out.
 */

import type { Arm32Program } from '../core/arm32/program';
import { arm32Unconditional, catalogKey, conditionOf, x86Unconditional } from '../core/catalog';
import type { CilProgram } from '../core/cil/program';
import { entryOf as cilEntryOf } from '../core/cil/program';
import type { Disassembly, Fn } from '../core/disassembly';
import { t } from '../core/i18n';
import { entryOf as jvmEntryOf, type JvmProgram } from '../core/jvm/program';
import type { Program } from '../core/program';
import type { Rows } from '../core/rows';
import { entryOf as wasmEntryOf, type WasmProgram } from '../core/wasm/program';
import type { X86Program } from '../core/x86/program';
import { arm32Follow, arm32Inspector, arm32RowHtml } from './arm32';
import { cilFollow, cilInspector, cilRowHtml, renderCilAssembly, renderCilImports } from './cil';
import { jvmFollow, jvmInspector, jvmRowHtml, renderJvmArchive, renderJvmImports } from './jvm';
import { fnName, settings, type Selection } from './state';
import { renderWasmImports, renderWasmModule, wasmFollow, wasmInspector, wasmRowHtml } from './wasm';
import { x86Follow, x86Inspector, x86RowHtml } from './x86';

/** Where Enter goes from an instruction: code, a string or data, or a member of another module. */
export interface Follow {
  code?: number;
  mem?: number;
  import?: Fn;
}

export interface View {
  /** What the page's title calls the tool. */
  title(): string;
  /** The tabs of the file's overview and of its imports. */
  overviewTab(): string;
  importsTab(): string;
  /** The listing's rows, the details panel, Enter: arm64 has its own (null). */
  rowHtml: ((rows: Rows, r: number, selected: boolean) => string) | null;
  inspector: ((sel: NonNullable<Selection>) => string) | null;
  follow: ((index: number) => Follow) | null;
  /** The functions and members of other modules, which have no code (bytecode only; native imports are the file's). */
  imported: Fn[] | null;
  /** A member of another module by the address the code names it with. */
  importAt(addr: number): Fn | undefined;
  /** How the command palette shows an import, and finds it: its name, with its module or assembly. */
  importText(fn: Fn): string;
  /** The Imports and overview pages: native code has the shared ones (null). */
  renderImports: ((page: HTMLElement) => void) | null;
  renderOverview: ((page: HTMLElement) => void) | null;
  /** Where the listing opens. */
  entry(): number | undefined;
  /** Where the functions the program exports start. */
  exports(): Set<number>;
  /** The mnemonic of what does not decode, and what the statistics call it. */
  unknown: string;
  unknownLabel(): string;
  /** The bytes of code. */
  codeBytes(): number;
  /** The statistics' option to count a mnemonic without its condition: the key it counts under, and the option's label. */
  joinKey: ((mnemonic: string) => string) | null;
  joinLabel(): string;
  /** Why the HLA64 view cannot show this program, if it cannot. */
  noHla(): string | null;
}

const views = new WeakMap<Disassembly, View>();

/** The view of a program. */
export function viewOf(p: Disassembly): View {
  let view = views.get(p);
  if (!view) {
    view = make(p);
    views.set(p, view);
  }
  return view;
}

const named = (fn: Fn) => fnName(fn);
const notDecoded = () => t('stats', 'instructions not decoded');
const wordsNotDecoded = () => t('stats', 'words not decoded');

function make(p: Disassembly): View {
  switch (p.arch) {
    case 'wasm':
      return wasmView(p as WasmProgram);
    case 'cil':
      return cilView(p as CilProgram);
    case 'jvm':
      return jvmView(p as JvmProgram);
    case 'arm32':
      return arm32View(p as Arm32Program);
    case 'x86':
      return x86View(p as X86Program);
    case 'arm64':
      return arm64View(p as Program);
  }
}

/** What WebAssembly, CIL and JVM programs have in common: no native file, imports with no code, no conditions to join. */
function bytecode(p: WasmProgram | CilProgram | JvmProgram) {
  return {
    importsTab: () => t('tabs', 'References'),
    imported: p.imported as Fn[],
    unknown: '.byte',
    unknownLabel: notDecoded,
    joinKey: null,
    joinLabel: () => '',
    noHla: () => null,
  };
}

function wasmView(p: WasmProgram): View {
  return {
    ...bytecode(p),
    title: () => t('bar', 'WebAssembly Disassembler'),
    overviewTab: () => t('tabs', 'Module'),
    importsTab: () => t('tabs', 'Imports and exports'),
    rowHtml: (rows, r, selected) => wasmRowHtml(p, rows, r, selected),
    inspector: (sel) => wasmInspector(p, sel),
    follow: (index) => wasmFollow(p, index),
    importAt: (addr) => p.imported.find((f) => f.addr === addr),
    importText: (fn) => `${fnName(fn)} (${(fn as WasmProgram['imported'][number]).module})`,
    renderImports: (page) => renderWasmImports(p, page),
    renderOverview: (page) => renderWasmModule(p, page),
    entry: () => wasmEntryOf(p)?.addr,
    exports: () => {
      const addrs = new Set<number>();
      for (const e of p.module.exports) {
        const fn = e.kind === 'func' ? p.func(e.index) : undefined;
        if (fn && fn.kind !== 'import') addrs.add(fn.addr);
      }
      return addrs;
    },
    unknown: '.bytes',
    codeBytes: () => p.module.sections.find((s) => s.id === 10)?.size ?? 0,
  };
}

function cilView(p: CilProgram): View {
  return {
    ...bytecode(p),
    title: () => t('bar', '.NET IL Disassembler'),
    overviewTab: () => t('tabs', 'Assembly'),
    rowHtml: (rows, r, selected) => cilRowHtml(p, rows, r, selected),
    inspector: (sel) => cilInspector(p, sel),
    follow: (index) => cilFollow(p, index),
    importAt: (addr) => p.importByToken.get(addr),
    importText: (fn) => `${fnName(fn)} (${(fn as CilProgram['imported'][number]).assembly})`,
    renderImports: (page) => renderCilImports(p, page),
    renderOverview: (page) => renderCilAssembly(p, page),
    entry: () => cilEntryOf(p)?.addr,
    exports: () => new Set(p.functions.filter((fn) => fn.kind === 'export').map((fn) => fn.addr)),
    codeBytes: () => p.bodies.reduce((n, b) => n + b.size, 0),
  };
}

function jvmView(p: JvmProgram): View {
  return {
    ...bytecode(p),
    title: () => t('bar', 'Java Bytecode Disassembler'),
    overviewTab: () => t('tabs', 'Classes'),
    rowHtml: (rows, r, selected) => jvmRowHtml(p, rows, r, selected),
    inspector: (sel) => jvmInspector(p, sel),
    follow: (index) => jvmFollow(p, index),
    importAt: (addr) => p.importByAddr.get(addr),
    importText: named,
    renderImports: (page) => renderJvmImports(p, page),
    renderOverview: (page) => renderJvmArchive(p, page),
    entry: () => jvmEntryOf(p)?.addr,
    // Public methods of public classes; the entry point is one too.
    exports: () => new Set(p.functions.filter((fn, f) => fn.kind === 'export' || (fn.kind === 'entry' && p.bodies[f]!.method.access & 1)).map((fn) => fn.addr)),
    codeBytes: () => p.bodies.reduce((n, b) => n + b.code.length, 0),
  };
}

/** What native programs have in common: a Mach-O, ELF or PE file with its imports and exports. */
function native(p: Program | Arm32Program | X86Program) {
  const file = p.image;
  return {
    overviewTab: () => (file.elf ? 'ELF' : file.pe ? 'PE' : t('tabs', 'Mach-O')),
    importsTab: () => (file.exports.length ? t('tabs', 'Imports and exports') : t('tabs', 'Imports')),
    imported: null,
    importAt: () => undefined,
    importText: named,
    renderImports: null,
    renderOverview: null,
    entry: () => nativeEntry(p),
    exports: () => new Set(file.exports.map((e) => e.addr)),
    noHla: () => null,
  };
}

function arm64View(p: Program): View {
  return {
    ...native(p),
    title: () => t('bar', 'ARM64 Disassembler'),
    rowHtml: null,
    inspector: null,
    follow: null,
    unknown: '.inst',
    unknownLabel: wordsNotDecoded,
    codeBytes: () => p.totalInstructions * 4,
    joinKey: (mnemonic) => (conditionOf(mnemonic) ? catalogKey(mnemonic) : mnemonic),
    joinLabel: () => t('stats', 'Count b.eq, b.ne… as one b.cond'),
  };
}

function arm32View(p: Arm32Program): View {
  return {
    ...native(p),
    title: () => t('bar', '32-bit Arm Disassembler'),
    rowHtml: (rows, r, selected) => arm32RowHtml(p, rows, r, selected, settings.bytes),
    inspector: (sel) => arm32Inspector(p, sel),
    follow: (index) => arm32Follow(p, index),
    unknown: '.inst',
    unknownLabel: wordsNotDecoded,
    codeBytes: () => p.ranges.reduce((n, r) => n + r.section.size, 0),
    joinKey: arm32Unconditional,
    joinLabel: () => t('stats', 'Count beq, addne… without their condition'),
    noHla: () => t('bar', 'HLA64 has no 32-bit Arm target: this code is shown as assembly.'),
  };
}

function x86View(p: X86Program): View {
  return {
    ...native(p),
    title: () => (p.mode === 64 ? t('bar', 'x86-64 Disassembler') : t('bar', 'x86 Disassembler')),
    rowHtml: (rows, r, selected) => x86RowHtml(p, rows, r, selected, settings.bytes),
    inspector: (sel) => x86Inspector(p, sel),
    follow: (index) => x86Follow(p, index),
    unknown: '<unknown>',
    unknownLabel: notDecoded,
    codeBytes: () => p.ranges.reduce((n, r) => n + r.section.size, 0),
    joinKey: x86Unconditional,
    joinLabel: () => t('stats', 'Count je, jne… as one jcc, cmovl, cmpltps… without their condition'),
    noHla: () => (p.mode === 32 ? t('bar', 'HLA64 has no 32-bit x86 target: this code is shown as assembly.') : null),
  };
}

/**
 * Where a native program opens: its entry point, or for a library what the
 * system calls first — JNI_OnLoad, a JNI method — or its first export.
 */
function nativeEntry(p: Program | Arm32Program | X86Program): number | undefined {
  const named = (test: (name: string) => boolean) => p.functions.find((f) => f.kind !== 'import' && f.raw !== undefined && test(f.raw))?.addr;
  // The program's own main, where one is known, rather than the C runtime's entry point before it.
  const main = named((n) => /^(_?main|wmain|w?WinMain)$/.test(n));
  if (main !== undefined) return main;
  // A 32-bit Arm entry point has the Thumb bit; 64-bit addresses must not go through `&`.
  const entry = p.image.entry === undefined ? undefined : p.arch === 'arm32' ? p.image.entry & ~1 : p.image.entry;
  if (entry !== undefined && p.indexOf(entry) >= 0) return entry;
  return named((n) => n === 'JNI_OnLoad') ?? named((n) => n.startsWith('Java_')) ?? p.functions.find((f) => f.kind === 'export')?.addr ?? p.functions[0]?.addr;
}
