/**
 * Symbol names back to source names, as the core reads them
 * (crates/core/src/demangle/): Rust v0 and legacy, C++ (Itanium), Swift in
 * full and in the simplified form `swift-demangle --simplified` gives, and
 * MSVC's names of Windows programs. A name that does not parse is returned as
 * it was.
 *
 * The page asks for the names it shows: one at a time for a row, a whole list
 * at once for a page of imports or exports (`demangleAll`), and keeps what it
 * was told.
 */

import { engine } from './engine/engine';

export interface Demangled {
  /** The full source name. */
  full: string;
  /** The same with generic arguments folded to <…>, for the listing. */
  short: string;
  language: 'rust' | 'c++' | 'c' | 'swift' | 'objc' | 'other';
}

/** What the names asked for so far read as: Mach-O's (a C name carries an underscore), and the others'. */
const caches = [new Map<string, Demangled>(), new Map<string, Demangled>()] as const;
/** Names kept at most, per kind, before the cache starts again. */
const KEEP = 1 << 19;

/** Reads every name of `raws` not read yet, in one call to the core. */
export function demangleAll(raws: Iterable<string>, unprefixed: boolean): void {
  const cache = caches[unprefixed ? 1 : 0];
  const wanted = [...new Set([...raws].filter((raw) => !cache.has(raw)))];
  if (!wanted.length) return;
  if (cache.size + wanted.length > KEEP) cache.clear();
  engine()
    .demangleNames(wanted, unprefixed)
    .forEach(([full, short, language], k) => {
      const raw = wanted[k]!;
      cache.set(raw, { full: full ?? raw, short: short ?? raw, language });
    });
}

function read(raw: string, unprefixed: boolean): Demangled {
  const cache = caches[unprefixed ? 1 : 0];
  let found = cache.get(raw);
  if (!found) {
    demangleAll([raw], unprefixed);
    found = cache.get(raw)!;
  }
  return found;
}

/** A Mach-O symbol: the leading underscore every C-level name carries is removed first. */
export function demangle(raw: string): Demangled {
  return read(raw, false);
}

/**
 * A name from an ELF file, a PE file or a WebAssembly module. There C names
 * carry no extra leading underscore (`main`, `_start`, `__cxa_finalize`), so
 * only mangled Rust, C++, Swift and MSVC names change; anything else stays as
 * the file writes it.
 */
export function demangleUnprefixed(raw: string): Demangled {
  return read(raw, true);
}

export const demangleWasm = demangleUnprefixed;

/* ------------------------------------------------------------------ *
 * For the tools that check the demanglers (tools/verify-msvc.mjs, tools/verify-swift.mjs)
 * ------------------------------------------------------------------ */

/** What LLVM's llvm-undname prints for each MSVC name with `flags` (its own numbering), or null. */
export function undnameAll(names: string[], flags = 0): (string | null)[] {
  return engine().demangleTool<string | null>(0, flags, names);
}

/** Each MSVC name in full and short, or null. */
export function demangleMsvcAll(names: string[]): ({ full: string; short: string } | null)[] {
  return engine()
    .demangleTool<[string, string] | null>(1, 0, names)
    .map((pair) => (pair ? { full: pair[0], short: pair[1] } : null));
}

/** Each Swift name in full and simplified, or null. */
export function demangleSwiftAll(names: string[]): ({ full: string; short: string } | null)[] {
  return engine()
    .demangleTool<[string, string] | null>(2, 0, names)
    .map((pair) => (pair ? { full: pair[0], short: pair[1] } : null));
}

/** Each Swift name's tree as `swift-demangle --tree-only` prints it, or null when it does not parse. */
export function swiftTreeAll(names: string[]): (string | null)[] {
  return engine().demangleTool<string | null>(3, 0, names);
}
