/**
 * Symbol names back to source names.
 *
 * - Rust v0 (`_R…`), what rustc emits by default since 1.80 for libraries
 *   built with it and what the program in front of us uses: a full parser of
 *   the grammar in RFC 2603, with back-references, generic arguments, impls,
 *   closures, function pointers and dyn traits.
 * - Rust legacy (`_ZN…17h<hash>E`): the hash is dropped and `$LT$`-style
 *   escapes are undone.
 * - C++ (Itanium) names: the nested name, with `(…)` for the parameters.
 * - Swift (`$s…`): src/core/swift.ts, in full and in the simplified form
 *   `swift-demangle --simplified` gives, which the listing shows.
 * - MSVC (`?f@@YAXXZ`), the names of Windows programs: src/core/msvc.ts.
 *
 * The leading underscore Mach-O adds to every C-level name is removed first.
 * A name that does not parse is returned as it was.
 */

import { demangleMsvc } from './msvc';
import { demangleSwift } from './swift';

const BASIC: Record<string, string> = {
  a: 'i8', b: 'bool', c: 'char', d: 'f64', e: 'str', f: 'f32', h: 'u8', i: 'isize', j: 'usize', l: 'i32', m: 'u32',
  n: 'i128', o: 'u128', s: 'i16', t: 'u16', u: '()', v: '...', x: 'i64', y: 'u64', z: '!', p: '_',
};

class Parse extends Error {}

class V0 {
  private depth = 0;
  /** Lifetimes bound by enclosing for<…> binders, innermost last. */
  private bound = 0;
  constructor(
    private readonly s: string,
    private pos: number,
  ) {}

  private peek(): string {
    return this.s[this.pos] ?? '';
  }
  private next(): string {
    const c = this.s[this.pos++];
    if (c === undefined) throw new Parse();
    return c;
  }
  private eat(c: string): boolean {
    if (this.s[this.pos] === c) {
      this.pos++;
      return true;
    }
    return false;
  }

  private base62(): number {
    if (this.eat('_')) return 0;
    let x = 0;
    for (;;) {
      const c = this.next();
      if (c === '_') return x + 1;
      const d = /[0-9]/.test(c) ? c.charCodeAt(0) - 48 : /[a-z]/.test(c) ? c.charCodeAt(0) - 87 : /[A-Z]/.test(c) ? c.charCodeAt(0) - 29 : -1;
      if (d < 0) throw new Parse();
      x = x * 62 + d;
    }
  }
  private optBase62(tag: string): number {
    return this.eat(tag) ? this.base62() + 1 : 0;
  }
  /** "0", or digits without a leading zero: in "0023_x" the 0, 0 and 23 are three numbers. */
  private decimal(): number {
    const start = this.pos;
    if (this.eat('0')) return 0;
    while (/[0-9]/.test(this.peek())) this.pos++;
    if (start === this.pos) throw new Parse();
    return Number(this.s.slice(start, this.pos));
  }

  private ident(): { name: string; disambiguator: number } {
    const disambiguator = this.optBase62('s');
    return { name: this.undisambiguated(), disambiguator };
  }
  private undisambiguated(): string {
    const punycode = this.eat('u');
    const length = this.decimal();
    this.eat('_');
    const name = this.s.slice(this.pos, this.pos + length);
    if (name.length !== length) throw new Parse();
    this.pos += length;
    return punycode ? `${name.replace(/_/g, '-')}` : name;
  }

  /** Runs `parse` at the position a back-reference points to, then comes back. */
  private backref<T>(parse: () => T): T {
    const target = this.base62() + 2; // offsets count from after "_R"
    if (target >= this.pos) throw new Parse();
    const saved = this.pos;
    this.pos = target;
    try {
      return parse();
    } finally {
      this.pos = saved;
    }
  }

  path(valueContext = true): string {
    if (++this.depth > 200) throw new Parse();
    try {
      const tag = this.next();
      switch (tag) {
        case 'C':
          return this.ident().name;
        case 'M': {
          this.optBase62('s');
          this.path(false);
          return `<${this.type()}>`;
        }
        case 'X': {
          this.optBase62('s');
          this.path(false);
          const type = this.type();
          return `<${type} as ${this.path(false)}>`;
        }
        case 'Y': {
          const type = this.type();
          return `<${type} as ${this.path(false)}>`;
        }
        case 'N': {
          const ns = this.next();
          const parent = this.path(valueContext);
          const { name, disambiguator } = this.ident();
          if (ns === 'C') return `${parent}::{closure${name ? `:${name}` : ''}#${disambiguator}}`;
          if (ns === 'S') return `${parent}::{shim${name ? `:${name}` : ''}#${disambiguator}}`;
          if (/[A-Z]/.test(ns)) return `${parent}::{${ns}${name ? `:${name}` : ''}#${disambiguator}}`;
          return name ? `${parent}::${name}` : parent;
        }
        case 'I': {
          const base = this.path(valueContext);
          const args: string[] = [];
          while (!this.eat('E')) args.push(this.genericArg());
          return `${base}${valueContext ? '::' : ''}<${args.join(', ')}>`;
        }
        case 'B':
          return this.backref(() => this.path(valueContext));
      }
      throw new Parse();
    } finally {
      this.depth--;
    }
  }

  private lifetimeName(n: number): string {
    if (n === 0) return "'_";
    const depth = this.bound - n;
    if (depth < 0) throw new Parse();
    return depth < 26 ? `'${String.fromCharCode(97 + depth)}` : `'_${depth}`;
  }

  /** Runs `body` with `count` more bound lifetimes, prefixing for<'a, …> when there are any. */
  private binder<T extends string>(count: number, body: () => T): string {
    if (!count) return body();
    this.bound += count;
    try {
      const first = this.bound - count;
      const list = [];
      for (let i = 0; i < count; i++) list.push(first + i < 26 ? `'${String.fromCharCode(97 + first + i)}` : `'_${first + i}`);
      return `for<${list.join(', ')}> ${body()}`;
    } finally {
      this.bound -= count;
    }
  }

  private genericArg(): string {
    if (this.eat('L')) return this.lifetimeName(this.base62());
    if (this.eat('K')) return this.constant();
    return this.type();
  }

  private lifetime(): string {
    if (!this.eat('L')) return '';
    const n = this.base62();
    return n ? `${this.lifetimeName(n)} ` : '';
  }

  type(): string {
    if (++this.depth > 200) throw new Parse();
    try {
      const c = this.peek();
      if (BASIC[c]) {
        this.pos++;
        return BASIC[c]!;
      }
      switch (c) {
        case 'A': {
          this.pos++;
          const t = this.type();
          return `[${t}; ${this.constant()}]`;
        }
        case 'S':
          this.pos++;
          return `[${this.type()}]`;
        case 'T': {
          this.pos++;
          const items: string[] = [];
          while (!this.eat('E')) items.push(this.type());
          return items.length === 1 ? `(${items[0]},)` : `(${items.join(', ')})`;
        }
        case 'R':
        case 'Q': {
          this.pos++;
          const lt = this.lifetime();
          return `&${lt}${c === 'Q' ? 'mut ' : ''}${this.type()}`;
        }
        case 'P':
          this.pos++;
          return `*const ${this.type()}`;
        case 'O':
          this.pos++;
          return `*mut ${this.type()}`;
        case 'F':
          this.pos++;
          return this.fnSig();
        case 'D': {
          this.pos++;
          const bounds = this.dynBounds();
          this.lifetimeAfterDyn();
          return `dyn ${bounds}`;
        }
        case 'B':
          this.pos++;
          return this.backref(() => this.type());
      }
      return this.path(false);
    } finally {
      this.depth--;
    }
  }

  private lifetimeAfterDyn(): void {
    if (this.eat('L')) this.base62();
  }

  private fnSig(): string {
    return this.binder(this.optBase62('G'), () => this.fnSigBody());
  }

  private fnSigBody(): string {
    const unsafe = this.eat('U');
    let abi = '';
    if (this.eat('K')) abi = this.eat('C') ? 'extern "C" ' : `extern "${this.undisambiguated().replace(/_/g, '-')}" `;
    const params: string[] = [];
    while (!this.eat('E')) params.push(this.type());
    const ret = this.type();
    return `${unsafe ? 'unsafe ' : ''}${abi}fn(${params.join(', ')})${ret === '()' ? '' : ` -> ${ret}`}`;
  }

  private dynBounds(): string {
    return this.binder(this.optBase62('G'), () => this.dynBoundsBody());
  }

  private dynBoundsBody(): string {
    const traits: string[] = [];
    while (!this.eat('E')) {
      let trait = this.path(false);
      const bindings: string[] = [];
      while (this.eat('p')) {
        const name = this.undisambiguated();
        bindings.push(`${name} = ${this.type()}`);
      }
      if (bindings.length) trait = trait.endsWith('>') ? `${trait.slice(0, -1)}, ${bindings.join(', ')}>` : `${trait}<${bindings.join(', ')}>`;
      traits.push(trait);
    }
    return traits.join(' + ');
  }

  private constant(): string {
    if (this.eat('p')) return '_';
    if (this.eat('B')) return this.backref(() => this.constant());
    const type = this.next();
    const negative = this.eat('n');
    const start = this.pos;
    while (this.peek() !== '_') {
      if (!/[0-9a-f]/.test(this.next())) throw new Parse();
    }
    const hex = this.s.slice(start, this.pos);
    this.pos++;
    if (type === 'b') return hex === '1' ? 'true' : 'false';
    if (type === 'c') return `'${String.fromCodePoint(parseInt(hex || '0', 16))}'`;
    const value = hex ? BigInt(`0x${hex}`) : 0n;
    return `${negative ? '-' : ''}${value}`;
  }

  symbol(): string {
    if (/[0-9]/.test(this.peek())) this.decimal(); // encoding version
    return this.path(true);
  }
}

function rustV0(name: string): string | null {
  // Back-references count from after "_R": the parser starts at 2 and adds 2 to every one.
  try {
    return new V0(name, 2).symbol();
  } catch {
    return null;
  }
}

const LEGACY_ESCAPES: Record<string, string> = {
  SP: '@', BP: '*', RF: '&', LT: '<', GT: '>', LP: '(', RP: ')', C: ',',
};

function rustLegacyComponent(part: string): string {
  let text = part.startsWith('_$') ? part.slice(1) : part;
  text = text.replace(/\$([A-Z]{1,2}|u[0-9a-f]{2,6})\$/g, (match, code: string) => {
    if (code.startsWith('u')) return String.fromCodePoint(parseInt(code.slice(1), 16));
    return LEGACY_ESCAPES[code] ?? match;
  });
  return text.replace(/\.\./g, '::');
}

/** Itanium nested names: _ZN <len><name>… E, as used by C++ and legacy Rust. */
function itanium(name: string): { parts: string[]; rest: string } | null {
  let p = 2;
  const parts: string[] = [];
  const nested = name[p] === 'N';
  if (nested) p++;
  while (name[p] === 'K' || name[p] === 'V' || name[p] === 'r') p++;
  do {
    if (name.startsWith('St', p)) {
      parts.push('std');
      p += 2;
      continue;
    }
    const match = /^\d+/.exec(name.slice(p));
    if (!match) {
      if (name[p] === 'C' && /[123]/.test(name[p + 1] ?? '')) {
        parts.push(parts.at(-1) ?? '');
        p += 2;
        continue;
      }
      if (name[p] === 'D' && /[012]/.test(name[p + 1] ?? '')) {
        parts.push(`~${parts.at(-1) ?? ''}`);
        p += 2;
        continue;
      }
      break;
    }
    const length = Number(match[0]);
    p += match[0].length;
    parts.push(name.slice(p, p + length));
    p += length;
  } while (nested && name[p] !== 'E' && p < name.length);
  if (!parts.length) return null;
  if (nested && name[p] === 'E') p++;
  return { parts, rest: name.slice(p) };
}

export interface Demangled {
  /** The full source name. */
  full: string;
  /** The same with generic arguments folded to <…>, for the listing. */
  short: string;
  language: 'rust' | 'c++' | 'c' | 'swift' | 'objc' | 'other';
}

/** Folds every <…> group (balanced) to <…>, keeping the outer path readable. */
export function foldGenerics(name: string): string {
  let out = '';
  let depth = 0;
  for (const c of name) {
    if (c === '<') {
      depth++;
      if (depth <= 2) out += depth === 2 ? '<…' : '<';
    } else if (c === '>' && depth > 0) {
      if (depth <= 2) out += '>';
      depth--;
    } else if (depth <= 1) out += c;
  }
  return out;
}

export function demangle(raw: string): Demangled {
  const name = raw.startsWith('__') || raw.startsWith('_$') ? raw.slice(1) : raw;
  if (name.startsWith('_R')) {
    const full = rustV0(name);
    if (full) return { full, short: foldGenerics(full), language: 'rust' };
    return { full: raw, short: raw, language: 'rust' };
  }
  if (name.startsWith('_ZN') || name.startsWith('_Z')) {
    const parsed = itanium(name);
    if (parsed) {
      const last = parsed.parts.at(-1) ?? '';
      if (/^h[0-9a-f]{16}$/.test(last) && parsed.parts.length > 1) {
        const full = parsed.parts.slice(0, -1).map(rustLegacyComponent).join('::');
        return { full, short: foldGenerics(full), language: 'rust' };
      }
      const params = parsed.rest && parsed.rest !== 'v' ? '(…)' : '()';
      const full = `${parsed.parts.join('::')}${params}`;
      return { full, short: full, language: 'c++' };
    }
  }
  if (name.startsWith('$s') || name.startsWith('$S') || name.startsWith('$e')) {
    const swift = demangleSwift(name);
    return swift ? { ...swift, language: 'swift' } : { full: raw, short: raw, language: 'swift' };
  }
  if (/^[+-]\[/.test(raw)) return { full: raw, short: raw, language: 'objc' };
  if (raw.startsWith('_')) return { full: raw.slice(1), short: raw.slice(1), language: 'c' };
  return { full: raw, short: raw, language: 'other' };
}

/**
 * A name from an ELF file or a WebAssembly module. There C names carry no
 * extra leading underscore (`main`, `_start`, `__cxa_finalize`), so only
 * mangled Rust, C++ and Swift names change; anything else stays as the file
 * writes it. A Windows program's C++ names are MSVC's (`?f@@YAXXZ`).
 */
export function demangleUnprefixed(raw: string): Demangled {
  if (raw.startsWith('$s') || raw.startsWith('$e')) return demangle(raw);
  if (raw.startsWith('?') || raw.startsWith('.?A')) {
    const msvc = demangleMsvc(raw);
    if (msvc) return { ...msvc, language: 'c++' };
  }
  if (raw.startsWith('_Z') || raw.startsWith('_R')) {
    const found = demangle(`_${raw}`);
    if (found.full !== `_${raw}`) return found;
  }
  return { full: raw, short: raw, language: 'other' };
}

export const demangleWasm = demangleUnprefixed;
