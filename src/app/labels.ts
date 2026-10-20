/**
 * Names the data uses as keys — instruction categories, flags, groups,
 * section and file types, sizes — in the interface language. Each is a
 * t() call with a literal, so tools/i18n.mjs finds them for the dictionaries.
 */

import { language, t } from '../core/i18n';

export function categoryLabel(category: string): string {
  switch (category) {
    case 'arithmetic': return t('category', 'arithmetic');
    case 'logic': return t('category', 'logic');
    case 'shift': return t('category', 'shift');
    case 'bitfield': return t('category', 'bitfield');
    case 'move': return t('category', 'move');
    case 'compare': return t('category', 'compare');
    case 'branch': return t('category', 'branch');
    case 'call': return t('category', 'call');
    case 'load': return t('category', 'load');
    case 'store': return t('category', 'store');
    case 'atomic': return t('category', 'atomic');
    case 'barrier': return t('category', 'barrier');
    case 'system': return t('category', 'system');
    case 'pointer-auth': return t('category', 'pointer authentication');
    case 'fp-arith': return t('category', 'FP arithmetic');
    case 'fp-convert': return t('category', 'FP conversion');
    case 'fp-compare': return t('category', 'FP compare');
    case 'fp-move': return t('category', 'FP move');
    case 'simd-arith': return t('category', 'SIMD arithmetic');
    case 'simd-logic': return t('category', 'SIMD logic');
    case 'simd-compare': return t('category', 'SIMD compare');
    case 'simd-shift': return t('category', 'SIMD shift');
    case 'simd-permute': return t('category', 'SIMD permute');
    case 'simd-load-store': return t('category', 'SIMD load and store');
    case 'simd-reduce': return t('category', 'SIMD reduce');
    case 'simd-convert': return t('category', 'SIMD conversion');
    case 'simd-move': return t('category', 'SIMD move');
    case 'crypto': return t('category', 'cryptography');
    case 'memory-copy': return t('category', 'memory copy and set');
    case 'hint': return t('category', 'hint');
    case 'coprocessor': return t('category', 'coprocessor');
    case 'parallel': return t('category', 'parallel (bytes and halfwords in a register)');
    case 'stack': return t('category', 'stack');
    case 'flags': return t('category', 'flags');
    case 'prefix': return t('category', 'prefix');
    case 'tile': return t('category', 'tiles (AMX)');
    case 'other': return t('category', 'other');
    case 'not decoded': return t('category', 'not decoded');
    case 'data': return t('category', 'data in the code');
    case 'variable': return t('category', 'variables');
    case 'structure': return t('category', 'blocks and loops');
    case 'memory': return t('category', 'memory size');
    case 'table': return t('category', 'tables');
    case 'reference': return t('category', 'references');
    case 'aggregate': return t('category', 'structs and arrays');
    case 'exception': return t('category', 'exceptions');
    case 'constant': return t('category', 'constants');
    case 'conversion': return t('category', 'conversion');
    case 'object': return t('category', 'objects');
    case 'array': return t('category', 'arrays');
  }
  return category;
}

export function flagsLabel(flags: string): string {
  switch (flags) {
    case 'sets NZCV': return t('flags', 'sets NZCV');
    case 'reads NZCV': return t('flags', 'reads NZCV');
    case 'reads and sets NZCV': return t('flags', 'reads and sets NZCV');
    case 'sets QC': return t('flags', 'sets QC');
    case 'sets Q': return t('flags', 'sets Q (saturation)');
    case 'sets GE': return t('flags', 'sets GE');
    case 'reads GE': return t('flags', 'reads GE');
    case 'can trap': return t('flags', 'can stop the program');
    case 'sets EFLAGS': return t('flags', 'sets EFLAGS');
    case 'reads EFLAGS': return t('flags', 'reads EFLAGS');
    case 'reads and sets EFLAGS': return t('flags', 'reads and sets EFLAGS');
    case 'can throw': return t('flags', 'can throw an exception');
  }
  return t('flags', 'no flags');
}

export function groupLabel(group: string): string {
  switch (group) {
    case 'base': return t('group', 'base');
    case 'fp': return t('group', 'floating point');
    case 'x87': return t('group', 'x87 floating point');
    case 'simd': return t('group', 'SIMD');
    case 'system': return t('group', 'system');
    case 'control': return t('group', 'control');
    case 'parametric': return t('group', 'parametric');
    case 'variable': return t('group', 'variables');
    case 'memory': return t('group', 'memory');
    case 'numeric': return t('group', 'numbers');
    case 'vector': return t('group', 'vectors');
    case 'reference': return t('group', 'references');
    case 'table': return t('group', 'tables');
    case 'aggregate': return t('group', 'structs and arrays');
    case 'exception': return t('group', 'exceptions');
    case 'atomic': return t('group', 'atomics');
    case 'il-base': return t('group', 'base');
    case 'il-object': return t('group', 'object model');
    case 'il-prefix': return t('group', 'prefix');
    case 'jvm-constants': return t('group', 'pushing constants');
    case 'jvm-loads': return t('group', 'loads');
    case 'jvm-stores': return t('group', 'stores');
    case 'jvm-stack': return t('group', 'stack operations');
    case 'jvm-math': return t('group', 'math');
    case 'jvm-conversions': return t('group', 'numeric conversions');
    case 'jvm-comparisons': return t('group', 'comparisons');
    case 'jvm-control': return t('group', 'control');
    case 'jvm-references': return t('group', 'object model');
    case 'jvm-extended': return t('group', 'extended');
  }
  return group;
}

/** The headings the reference list groups instructions under. */
export function groupHeading(group: string): string {
  switch (group) {
    case 'base': return t('group', 'Integer, memory and branches');
    case 'fp': return t('group', 'Floating point');
    case 'simd': return t('group', 'SIMD (NEON)');
    case 'system': return t('group', 'System');
    case 'control': return t('group', 'Control: blocks, branches, calls');
    case 'parametric': return t('group', 'Stack: drop and select');
    case 'variable': return t('group', 'Locals and globals');
    case 'memory': return t('group', 'Memory');
    case 'numeric': return t('group', 'Numbers');
    case 'vector': return t('group', 'Vectors (SIMD)');
    case 'reference': return t('group', 'References');
    case 'table': return t('group', 'Tables');
    case 'aggregate': return t('group', 'Structs and arrays (GC)');
    case 'exception': return t('group', 'Exceptions');
    case 'atomic': return t('group', 'Atomics (threads)');
    case 'il-base': return t('group', 'Base instructions');
    case 'il-object': return t('group', 'Object model');
    case 'il-prefix': return t('group', 'Prefixes');
    case 'jvm-constants': return t('group', 'Constants');
    case 'jvm-loads': return t('group', 'Loads: locals and array elements');
    case 'jvm-stores': return t('group', 'Stores: locals and array elements');
    case 'jvm-stack': return t('group', 'Stack');
    case 'jvm-math': return t('group', 'Arithmetic');
    case 'jvm-conversions': return t('group', 'Conversions');
    case 'jvm-comparisons': return t('group', 'Comparisons and conditional branches');
    case 'jvm-control': return t('group', 'Control: branches, switches, returns');
    case 'jvm-references': return t('group', 'Objects, fields, calls, arrays');
    case 'jvm-extended': return t('group', 'Extended: wide forms, multidimensional arrays, null tests');
  }
  return group;
}

export function fileTypeLabel(type: number, fallback: string): string {
  switch (type) {
    case 1: return t('filetype', 'Object file');
    case 2: return t('filetype', 'Executable');
    case 6: return t('filetype', 'Dynamic library');
    case 7: return t('filetype', 'Dynamic linker');
    case 8: return t('filetype', 'Bundle');
    case 9: return t('filetype', 'Dynamic library stub');
    case 10: return t('filetype', 'Debug symbols (dSYM)');
    case 11: return t('filetype', 'Kernel extension');
  }
  return fallback;
}

export function sectionTypeLabel(type: number): string {
  switch (type) {
    case 0: return t('section', 'regular');
    case 1: return t('section', 'zerofill');
    case 2: return t('section', 'C strings');
    case 3: return t('section', '4-byte literals');
    case 4: return t('section', '8-byte literals');
    case 5: return t('section', 'literal pointers');
    case 6: return t('section', 'non-lazy pointers');
    case 7: return t('section', 'lazy pointers');
    case 8: return t('section', 'symbol stubs');
    case 9: return t('section', 'init functions');
    case 10: return t('section', 'term functions');
    case 11: return t('section', 'coalesced');
    case 12: return t('section', 'gigabyte zerofill');
    case 13: return t('section', 'interposing');
    case 14: return t('section', '16-byte literals');
    case 16: return t('section', 'lazy dylib pointers');
    case 17: return t('section', 'thread-local data');
    case 18: return t('section', 'thread-local zerofill');
    case 19: return t('section', 'thread-local variables');
    case 20: return t('section', 'thread-local pointers');
    case 21: return t('section', 'thread-local init functions');
    case 22: return t('section', 'init function offsets');
  }
  return '';
}

/** A size in bytes, as the interface writes it. */
export function sizeLabel(bytes: number): string {
  if (bytes >= 1048576) return t('units', '{n} MB', { n: (bytes / 1048576).toLocaleString(language(), { maximumFractionDigits: 1 }) });
  if (bytes >= 1024) return t('units', '{n} KB', { n: (bytes / 1024).toLocaleString(language(), { maximumFractionDigits: 1 }) });
  return t('units', '{n} B', { n: bytes });
}

export function secondsLabel(seconds: number): string {
  return t('units', '{n} s', { n: seconds.toLocaleString(language(), { minimumFractionDigits: 2, maximumFractionDigits: 2 }) });
}
