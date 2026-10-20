/**
 * What every disassembled program has, whatever its architecture: the
 * instructions as small typed arrays (a mnemonic number and a few flag bits
 * each), the functions, the labels, the call and data cross references and
 * the strings. The listing, the pages and the search work on this; the
 * architectures add what is theirs — src/core/program.ts for an arm64
 * Mach-O, src/core/wasm/program.ts for a WebAssembly module.
 */

export interface Fn {
  addr: number;
  /** Index of its first instruction, and how many it has. */
  first: number;
  count: number;
  /** As the listing shows it: demangled, generic arguments folded. */
  name: string;
  /** The full demangled name, and the symbol as it is in the file. */
  full: string;
  raw?: string;
  kind: 'export' | 'symbol' | 'import' | 'entry' | 'anonymous';
  language?: string;
  /** A WebAssembly function's index in the module's function index space. */
  index?: number;
}

export interface StringRef {
  addr: number;
  text: string;
  section: string;
  /** NUL-terminated C string, or a run of printable bytes in constant data. */
  kind: 'cstring' | 'const';
}

export interface MnemonicCount {
  mnemonic: string;
  count: number;
}

/** A run of code the listing shows under one heading: a section of a Mach-O, the code section of a module. */
export interface CodeRange {
  name: string;
  /** Index of the first instruction, and how many there are. */
  first: number;
  count: number;
}

/** Bits of Disassembly.flags, one byte per instruction. */
export const IF = {
  LABEL: 1, // a branch lands here
  FUSE: 2, // reads as one HLA64 line together with the next instruction
  FUNCTION: 4, // a function starts here
  CALL: 8, // bl / blr, call / call_indirect
  UNKNOWN: 16, // not a decodable instruction
  BRANCH: 32,
} as const;

export type Arch = 'arm64' | 'arm32' | 'x86' | 'wasm' | 'cil' | 'jvm';

/** What a data address holds, as the views name it. */
/** What is at a data address. A string with `objc` set is a constant NSString (`@"text"`), its text the characters. */
export type DataAt = { kind: 'string'; text: string; objc?: boolean } | { kind: 'symbol'; name: string } | undefined;

export abstract class Disassembly {
  abstract readonly arch: Arch;
  readonly ranges: CodeRange[] = [];
  mnemonicIds = new Uint16Array(0);
  flags = new Uint8Array(0);
  readonly mnemonics: string[] = [];
  readonly functions: Fn[] = [];
  /** First-instruction index → function index. */
  readonly functionAtIndex = new Map<number, number>();
  /** Call target → call sites; data address → instructions that build or read it. */
  readonly callers = new Map<number, number[]>();
  readonly dataRefs = new Map<number, number[]>();
  /**
   * Calls through an import's slot rather than a stub (`call qword ptr [rip + …]`, or on Arm a
   * register loaded from the slot — `blr x8`): slot → call sites, and instruction index → slot.
   */
  readonly slotCallers = new Map<number, number[]>();
  readonly slotCalls = new Map<number, number>();
  readonly strings: StringRef[] = [];
  readonly stringAt = new Map<number, StringRef>();
  counts: MnemonicCount[] = [];
  totalInstructions = 0;
  decodeMs = 0;

  /** The address of an instruction. */
  abstract addrOf(index: number): number;
  /** The instruction index of an address in code, or -1. */
  abstract indexOf(addr: number): number;
  /** Where the branch at an instruction goes, as instruction indices (none for anything else). */
  abstract branchTargets(index: number): number[];
  /** What is at a data address: a string, a named symbol. */
  abstract dataAt(addr: number): DataAt;
  /** The name of the architecture as the file chip shows it. */
  abstract archLabel(): string;
  /** How many instructions from `index` (before `end`) are the same padding, filling the space between functions; 0 if it is not padding. */
  paddingRun(_index: number, _end: number): number {
    return 0;
  }

  /** Lets go of what the program keeps in the core (a session with its classes); it still works, reading them again if asked. */
  dispose(): void {}

  /** The system the program is built for, when the file says: `Android 5.0+`, `macOS 14.0+`. */
  platformLabel(): string | undefined {
    return undefined;
  }

  rangeOfIndex(index: number): CodeRange | undefined {
    for (const range of this.ranges) if (index >= range.first && index < range.first + range.count) return range;
    return undefined;
  }

  /** The function an instruction index belongs to (binary search), or -1. */
  functionOfIndex(index: number): number {
    let lo = 0;
    let hi = this.functions.length - 1;
    let found = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const fn = this.functions[mid]!;
      if (fn.first <= index) {
        found = mid;
        lo = mid + 1;
      } else hi = mid - 1;
    }
    if (found < 0) return -1;
    const fn = this.functions[found]!;
    return index < fn.first + fn.count ? found : -1;
  }

  functionAt(addr: number): Fn | undefined {
    const index = this.indexOf(addr);
    if (index < 0) return undefined;
    const at = this.functionAtIndex.get(index);
    return at === undefined ? undefined : this.functions[at];
  }

  labelName(addr: number): string {
    return `L${addr.toString(16)}`;
  }

  /** Counts the mnemonics, most frequent first, from the per-mnemonic tallies. */
  tally(counts: number[]): void {
    this.counts = this.mnemonics.map((mnemonic, id) => ({ mnemonic, count: counts[id]! })).sort((a, b) => b.count - a.count || a.mnemonic.localeCompare(b.mnemonic));
  }
}

/**
 * A program of bytecode — WebAssembly, CIL, JVM — whose instructions are
 * known by their addresses, in order, and whose branches by their targets.
 */
export abstract class BytecodeProgram extends Disassembly {
  /** Instruction index → address: an offset in the file, an RVA, or one the analysis gives. */
  offsets = new Uint32Array(0);
  /** Branch → where it goes (instruction indices). */
  readonly targets = new Map<number, number | number[]>();

  addrOf(index: number): number {
    return this.offsets[index] ?? 0;
  }

  /** The instruction at an address (binary search), or -1. */
  indexOf(addr: number): number {
    const offsets = this.offsets;
    let lo = 0;
    let hi = this.totalInstructions - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const at = offsets[mid]!;
      if (at === addr) return mid;
      if (at < addr) lo = mid + 1;
      else hi = mid - 1;
    }
    return -1;
  }

  branchTargets(index: number): number[] {
    const target = this.targets.get(index);
    if (target === undefined) return [];
    return typeof target === 'number' ? [target] : target;
  }

  /** The last instruction of the HLA64 line an instruction is in: the analysis marks each one joined to the next (IF.FUSE). */
  joinedTo(index: number): number {
    let last = index;
    while (this.flags[last]! & IF.FUSE && last + 1 < this.totalInstructions) last++;
    return last;
  }

  /** The first and last instructions of the HLA64 line an instruction is in. */
  joined(index: number): [number, number] {
    let first = index;
    while (first > 0 && this.flags[first - 1]! & IF.FUSE) first--;
    return [first, this.joinedTo(index)];
  }
}

/** Adds a value to the list a map holds for a key. */
export function append<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}

/** Printable ASCII, tab, newline, and the bytes of UTF-8 sequences. */
export function isText(b: number): boolean {
  return (b >= 0x20 && b < 0x7f) || b === 9 || b === 10 || b === 13 || b >= 0xc2;
}

export const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

/** The steps of an analysis, for a progress bar: the page names them. */
export type Stage = 'decode' | 'functions' | 'done';

export interface Progress {
  (stage: Stage, done: number, total: number): void;
}
