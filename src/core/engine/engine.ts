/**
 * The Rust core (crates/), compiled to WebAssembly, as the rest of the
 * TypeScript sees it.
 *
 * The module imports nothing and knows nothing of its host: the bundler puts
 * its bytes in (`target/core.wasm`, built by tools/wasm.mjs), and the same
 * code runs in the page, in Node for the tests, or in a desktop shell.
 *
 * How work crosses the boundary, and why it is cheap:
 *
 * - a file goes in once — one copy into the module's memory;
 * - a whole program is analysed inside, in steps the caller paces (the page
 *   shows progress between them); nothing calls back per instruction;
 * - the results are flat arrays, copied out in one go each (a few
 *   milliseconds for millions of instructions) so that later growth of the
 *   module's memory cannot detach them;
 * - small questions — one instruction for a row on screen — are one call,
 *   the answer a short JSON text.
 *
 * A panic in the core traps; the engine reports the core's message and starts
 * a fresh instance for the next call, since the trapped one may be left
 * half-way through a change.
 */

import wasm from '../../../target/core.wasm';

interface Exports {
  memory: WebAssembly.Memory;
  init(): void;
  error_ptr(): number;
  error_len(): number;
  alloc(len: number): number;
  dealloc(ptr: number, len: number): void;
  out_ptr(): number;
  close(handle: number): void;
  view(handle: number, id: number): number;
  view_len(handle: number, id: number): number;
  arm64_step(handle: number, budget: number): number;
  arm64_done(handle: number): number;
  arm64_total(handle: number): number;
  arm64_mnemonics(handle: number): number;
  arm64_decode(word: number, pc: number): number;
  arm64_text(word: number, pc: number): number;
  arm64_hla(word: number, pc: number, next: number, nextPc: number, mode: number, input: number, len: number): number;
  arm64_paired(word: number, pc: number, next: number, nextPc: number): number;
  x86_hla(fused: number, input: number, len: number): number;
  wasm_hla(handle: number, first: number, last: number, input: number, len: number): number;
  cil_hla(handle: number, first: number, last: number): number;
  jvm_hla(handle: number, first: number, last: number, input: number, len: number): number;
  demangle_names(input: number, len: number, unprefixed: number): number;
  arm64_assemble(pc: number, input: number, len: number): number;
  wasm_parse(bytes: number, len: number): number;
  wasm_insn(handle: number, index: number): number;
  wasm_fn_refs(handle: number, first: number, count: number): number;
  wasm_lines(handle: number): number;
  wasm_decode(bytes: number, len: number): number;
  jvm_insn(handle: number, index: number): number;
  jvm_method(handle: number, fnIndex: number): number;
  jvm_class_info(handle: number, k: number): number;
  jvm_fn_refs(handle: number, fnIndex: number): number;
  jvm_escape(units: number, len: number): number;
  wasm_print(bytes: number, len: number): number;
  demangle_tool(what: number, flags: number, input: number, len: number): number;
  x86_step(handle: number, budget: number): number;
  x86_decode(bytes: number, len: number, addr: number, mode: number): number;
  arm32_step(handle: number, budget: number): number;
  arm32_mapped(handle: number): number;
  arm32_decode(kind: number, word: number, pc: number, it: number): number;
  arm32_ignores_it(word: number): number;
  jvm_open(bytes: number, len: number, analyse: number): number;
  jvm_open_error(): number;
  jvm_step(handle: number, budget: number): number;
  jvm_done(handle: number): number;
  jvm_total(handle: number): number;
  jvm_text(handle: number, what: number): number;
  wasm_open(bytes: number, len: number): number;
  wasm_step(handle: number, budget: number): number;
  wasm_done(handle: number): number;
  wasm_total(handle: number): number;
  wasm_text(handle: number, what: number): number;
  cil_open(bytes: number, len: number, sections: number, count: number, clr: number): number;
  cil_step(handle: number, budget: number): number;
  cil_done(handle: number): number;
  cil_total(handle: number): number;
  cil_text(handle: number, what: number): number;
  cil_open_error(): number;
  cil_insn(handle: number, index: number): number;
  cil_method(handle: number, fnIndex: number): number;
  cil_fn_refs(handle: number, fnIndex: number): number;
  cil_field(handle: number, tok: number): number;
  cil_user_string(handle: number, index: number): number;
  cil_string_text(handle: number, index: number): number;
  cil_assembly(handle: number): number;
  cil_references(handle: number): number;
  macho_parse(bytes: number, len: number, want: number, wantLen: number): number;
  elf_parse(bytes: number, len: number): number;
  pe_parse(bytes: number, len: number): number;
  native_open(bytes: number, len: number, container: number, arch: number): number;
  native_finish(handle: number): void;
  native_text(handle: number, what: number): number;
  native_image(bytes: number, len: number, container: number): number;
  archive_open(bytes: number, len: number): number;
  archive_names(handle: number): number;
  archive_programs(handle: number): number;
  archive_libraries(handle: number): number;
  archive_read(handle: number, what: number, k: number): number;
  macho_resign(bytes: number, len: number): number;
}

/** Something the core could not do: its own message, after a trap. */
export class CoreError extends Error {}

const utf8 = new TextDecoder();

let module: WebAssembly.Module | null = null;
let current: Engine | null = null;
let loading: Promise<Engine> | null = null;

/** The engine, compiled and started on the first call. */
export function loadEngine(): Promise<Engine> {
  if (current) return Promise.resolve(current);
  loading ??= (async () => {
    module ??= await WebAssembly.compile(wasm as Uint8Array<ArrayBuffer>);
    current = new Engine(await WebAssembly.instantiate(module, {}));
    return current;
  })().finally(() => {
    loading = null;
  });
  return loading;
}

/** Waits until the engine can be used without waiting: `engine()` works from then on. */
export async function ready(): Promise<void> {
  await loadEngine();
}

/** The engine, which must have been loaded (`loadEngine`, `ready`): every analysis awaits it first. */
export function engine(): Engine {
  if (current) return current;
  if (module) {
    // A trap dropped the last instance: a new one starts at once from the compiled module.
    current = new Engine(new WebAssembly.Instance(module, {}));
    return current;
  }
  throw new Error('The core is not loaded yet: await loadEngine() first');
}

export class Engine {
  readonly x: Exports;

  constructor(instance: WebAssembly.Instance) {
    this.x = instance.exports as unknown as Exports;
    this.x.init();
  }

  /** Runs a call into the core, turning a trap into the core's own message. */
  call<T>(run: () => T): T {
    try {
      return run();
    } catch (err) {
      if (err instanceof WebAssembly.RuntimeError) {
        const len = this.x.error_len();
        const message = len ? utf8.decode(new Uint8Array(this.x.memory.buffer, this.x.error_ptr() >>> 0, len)) : err.message;
        if (current === this) current = null;
        throw new CoreError(`The core failed: ${message}`);
      }
      throw err;
    }
  }

  /** The text the last call left in the output buffer. */
  out(len: number): string {
    return utf8.decode(new Uint8Array(this.x.memory.buffer, this.x.out_ptr() >>> 0, len));
  }

  /** Copies bytes into the module's memory; free them with `free`. */
  put(bytes: Uint8Array): number {
    // A pointer past 2 GiB comes back as a negative i32: read as unsigned, it is the same address.
    const ptr = this.x.alloc(bytes.length) >>> 0;
    new Uint8Array(this.x.memory.buffer, ptr, bytes.length).set(bytes);
    return ptr;
  }

  putF64(values: ArrayLike<number>): { ptr: number; bytes: number } {
    const bytes = values.length * 8;
    const ptr = this.x.alloc(bytes) >>> 0;
    new Float64Array(this.x.memory.buffer, ptr, values.length).set(values);
    return { ptr, bytes };
  }

  free(ptr: number, bytes: number): void {
    this.x.dealloc(ptr, bytes);
  }

  /** A copy of one of a session's arrays (see `view_of` in crates/wasm). */
  copy<T extends TypedArray>(handle: number, id: number, Kind: TypedArrayKind<T>): T {
    const ptr = this.x.view(handle, id) >>> 0;
    const len = this.x.view_len(handle, id) >>> 0;
    if (!len) return new Kind(0);
    return new Kind(this.x.memory.buffer as ArrayBuffer, ptr, len).slice() as T;
  }

  /** One arm64 instruction, decoded at an address. */
  arm64Decode<I>(word: number, pc: number): I {
    return JSON.parse(this.out(this.call(() => this.x.arm64_decode(word >>> 0, pc)))) as I;
  }

  /** One x86 instruction from its bytes (it and what follows it in its section), decoded and printed: the JSON `x86_decode` writes. */
  x86Decode<D extends { length: number }>(bytes: Uint8Array, addr: number, mode: 64 | 32): D {
    // An instruction is fifteen bytes at most, but the decoder takes any number of prefixes before
    // one, as LLVM's does: the rest of the section goes in only for such a run.
    const read = (len: number): D => {
      const ptr = this.scratch(len);
      new Uint8Array(this.x.memory.buffer, ptr, len).set(bytes.subarray(0, len));
      return JSON.parse(this.out(this.call(() => this.x.x86_decode(ptr, len, addr, mode))), (key, value) =>
        key !== '' && value && typeof value === 'object' && typeof value.big === 'string' ? BigInt(value.big) : value,
      ) as D;
    };
    const first = read(Math.min(bytes.length, 32));
    return first.length > 17 && bytes.length > 32 ? read(bytes.length) : first;
  }

  /** One round of an arm64 HLA64 line (crates/wasm/src/hla.rs): the line, or the questions it needs answered, as JSON. */
  arm64Hla(word: number, pc: number, next: number, nextPc: number, mode: number, input: Uint8Array): string {
    const ptr = this.hand(input);
    return this.out(this.call(() => this.x.arm64_hla(word >>> 0, pc, next >>> 0, nextPc, mode, ptr, input.length)));
  }

  /** The address an adrp and the instruction after it build; NaN when they do not. */
  arm64Paired(word: number, pc: number, next: number, nextPc: number): number {
    return this.call(() => this.x.arm64_paired(word >>> 0, pc, next >>> 0, nextPc));
  }

  /** One round of an x86-64 HLA64 line, the instruction (and with `fused` the next) written in `input`. */
  x86Hla(fused: boolean, input: Uint8Array): string {
    const ptr = this.hand(input);
    return this.out(this.call(() => this.x.x86_hla(fused ? 1 : 0, ptr, input.length)));
  }

  /** One round of the HLA64 line of WebAssembly instructions first..last, in a module's session. */
  wasmHla(handle: number, first: number, last: number, input: Uint8Array): string {
    const ptr = this.hand(input);
    return this.out(this.call(() => this.x.wasm_hla(handle, first, last, ptr, input.length)));
  }

  /** The HLA64 line of CIL instructions first..last, in an assembly's session: JSON. */
  cilHla(handle: number, first: number, last: number): string {
    return this.out(this.call(() => this.x.cil_hla(handle, first, last)));
  }

  /** One round of the HLA64 line of Java instructions first..last, in a session that analysed them. */
  jvmHla(handle: number, first: number, last: number, input: Uint8Array): string {
    const ptr = this.hand(input);
    return this.out(this.call(() => this.x.jvm_hla(handle, first, last, ptr, input.length)));
  }

  /** What each name reads as back in source (crates/wasm/src/demangle.rs): [full, short, language], null where it is the name itself. */
  demangleNames(names: string[], unprefixed: boolean): [string | null, string | null, 'rust' | 'c++' | 'c' | 'swift' | 'objc' | 'other'][] {
    return this.withNames(names, (ptr, len) => this.x.demangle_names(ptr, len, unprefixed ? 1 : 0));
  }

  /** One of the demanglers over many names, for the tools that check them: see `demangle_tool`. */
  demangleTool<T>(what: number, flags: number, names: string[]): T[] {
    return this.withNames(names, (ptr, len) => this.x.demangle_tool(what, flags, ptr, len));
  }

  /** Hands names over separated by NUL, runs a call on them and reads the JSON it leaves. */
  private withNames<T>(names: string[], run: (ptr: number, len: number) => number): T {
    const bytes = utf8Encoder.encode(names.join('\0'));
    const ptr = this.put(bytes);
    try {
      return JSON.parse(this.out(this.call(() => run(ptr, bytes.length)))) as T;
    } finally {
      this.free(ptr, bytes.length);
    }
  }

  /** One round of assembling an arm64 line (crates/wasm/src/assemble.rs): its word, its error, or the names it needs. */
  arm64Assemble(pc: number, input: Uint8Array): string {
    const ptr = this.hand(input);
    return this.out(this.call(() => this.x.arm64_assemble(pc, ptr, input.length)));
  }

  /** A WebAssembly module read by the core (crates/wasm/src/wasm_module.rs): its JSON, BigInts back as BigInts. */
  wasmParse<T>(bytes: Uint8Array): T {
    const ptr = this.put(bytes);
    try {
      return withBigInts(this.out(this.call(() => this.x.wasm_parse(ptr, bytes.length)))) as T;
    } finally {
      this.free(ptr, bytes.length);
    }
  }

  /** One instruction of a module's session, for a row: the JSON `wasm_insn` writes, or null. */
  wasmInsn<T>(handle: number, index: number): T {
    return withBigInts(this.out(this.call(() => this.x.wasm_insn(handle, index)))) as T;
  }

  /** What a function's instructions call and name: the JSON `wasm_fn_refs` writes. */
  wasmFnRefs<T>(handle: number, first: number, count: number): T {
    return JSON.parse(this.out(this.call(() => this.x.wasm_fn_refs(handle, first, count)))) as T;
  }

  /** The first instruction of some bytes, with no module around them (for the tests). */
  wasmDecode<T>(bytes: Uint8Array): T {
    const ptr = this.hand(bytes);
    return withBigInts(this.out(this.call(() => this.x.wasm_decode(ptr, bytes.length)))) as T;
  }

  /** Every instruction of a module's bodies as text, a line each (`wasm_print`, for tools/verify-wasm.mjs). */
  wasmPrint(bytes: Uint8Array): string {
    const ptr = this.put(bytes);
    try {
      return this.out(this.call(() => this.x.wasm_print(ptr, bytes.length)));
    } finally {
      this.free(ptr, bytes.length);
    }
  }

  /** One of the questions the Java or the .NET page asks of a session (crates/wasm/src/jvm_page.rs, cil_page.rs): the JSON the call writes. */
  pageJson<T>(call: () => number): T {
    return JSON.parse(this.out(this.call(call))) as T;
  }

  /** A string as javap writes it in a comment; its UTF-16 units go over as they are, lone surrogates too. */
  jvmEscape(text: string): string {
    const units = new Uint8Array(text.length * 2);
    for (let k = 0; k < text.length; k++) {
      const u = text.charCodeAt(k);
      units[k * 2] = u & 0xff;
      units[k * 2 + 1] = u >> 8;
    }
    const ptr = this.put(units);
    try {
      return JSON.parse(this.out(this.call(() => this.x.jvm_escape(ptr, units.length)))) as string;
    } finally {
      this.free(ptr, units.length);
    }
  }

  /** The source files of a module's DWARF line table, or null; its rows are then views 27 and 28. */
  wasmLines(handle: number): string[] | null {
    return JSON.parse(this.out(this.call(() => this.x.wasm_lines(handle)))) as string[] | null;
  }

  /** Copies a few bytes into the scratch buffer for a call that reads them. */
  private hand(bytes: Uint8Array): number {
    const ptr = this.scratch(bytes.length);
    new Uint8Array(this.x.memory.buffer, ptr, bytes.length).set(bytes);
    return ptr;
  }

  private scratchPtr = 0;
  private scratchLen = 0;

  /** A buffer kept for the calls that hand over a few bytes each (x86_decode, the HLA64 lines). */
  private scratch(len: number): number {
    if (len > this.scratchLen) {
      if (this.scratchPtr) this.x.dealloc(this.scratchPtr, this.scratchLen);
      this.scratchLen = Math.max(32, len);
      this.scratchPtr = this.x.alloc(this.scratchLen) >>> 0;
    }
    return this.scratchPtr;
  }

  /** One AArch32 entry (A32, T16, T32 by kind) decoded at an address, with the IT condition it runs under (-1 for none). */
  arm32Decode<I>(kind: number, word: number, pc: number, it: number): I {
    return JSON.parse(this.out(this.call(() => this.x.arm32_decode(kind, word >>> 0, pc, it)))) as I;
  }

  /** A Mach-O file read by the core: the JSON `macho_parse` writes. */
  machoParse<T>(file: Uint8Array, want: string): T {
    const name = utf8Encoder.encode(want);
    const ptr = this.put(file);
    const w = this.put(name);
    try {
      return JSON.parse(this.out(this.call(() => this.x.macho_parse(ptr, file.length, w, name.length)))) as T;
    } finally {
      this.free(ptr, file.length);
      this.free(w, name.length);
    }
  }

  /** An ELF or PE file read by the core: the JSON its parser writes. */
  containerParse<T>(kind: 'elf' | 'pe', file: Uint8Array): T {
    const ptr = this.put(file);
    try {
      return JSON.parse(this.out(this.call(() => this.x[`${kind}_parse`](ptr, file.length)))) as T;
    } finally {
      this.free(ptr, file.length);
    }
  }

  /** A native program's image as the core builds it (crates/wasm/src/native_image.rs): 0 Mach-O, 1 ELF, 2 PE's Arm code, 3 PE's x64 code. */
  nativeImage<T>(file: Uint8Array, container: number): T | null {
    const ptr = this.put(file);
    try {
      return JSON.parse(this.out(this.call(() => this.x.native_image(ptr, file.length, container)))) as T | null;
    } finally {
      this.free(ptr, file.length);
    }
  }

  /** One arm64 instruction as llvm-objdump prints it. */
  arm64Text(word: number, pc: number): string {
    return this.out(this.call(() => this.x.arm64_text(word >>> 0, pc)));
  }
}

type TypedArray = Uint8Array<ArrayBuffer> | Uint16Array<ArrayBuffer> | Uint32Array<ArrayBuffer> | Int32Array<ArrayBuffer> | Float64Array<ArrayBuffer>;
interface TypedArrayKind<T extends TypedArray> {
  new (length: number): T;
  new (buffer: ArrayBuffer, byteOffset: number, length: number): T;
}

/**
 * Cross references as the core hands them over — keys ascending, where each
 * key's run starts, instruction indices — read like the `Map<number, number[]>`
 * the rest of the code expects: a key's references come back as addresses.
 * Nothing can be added to it.
 */
export class RefMap extends Map<number, number[]> {
  constructor(
    private readonly keyList: Float64Array,
    private readonly starts: Uint32Array,
    private readonly refs: Uint32Array,
    private readonly addrOf: (index: number) => number,
  ) {
    super();
  }

  private find(key: number): number {
    const keys = this.keyList;
    let lo = 0;
    let hi = keys.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const at = keys[mid]!;
      if (at === key) return mid;
      if (at < key) lo = mid + 1;
      else hi = mid - 1;
    }
    return -1;
  }

  private run(k: number): number[] {
    const out: number[] = [];
    for (let i = this.starts[k]!; i < this.starts[k + 1]!; i++) out.push(this.addrOf(this.refs[i]!));
    return out;
  }

  override get(key: number): number[] | undefined {
    const k = this.find(key);
    return k < 0 ? undefined : this.run(k);
  }

  override has(key: number): boolean {
    return this.find(key) >= 0;
  }

  override get size(): number {
    return this.keyList.length;
  }

  override *keys(): MapIterator<number> {
    for (let k = 0; k < this.keyList.length; k++) yield this.keyList[k]!;
  }

  override *values(): MapIterator<number[]> {
    for (let k = 0; k < this.keyList.length; k++) yield this.run(k);
  }

  override *entries(): MapIterator<[number, number[]]> {
    for (let k = 0; k < this.keyList.length; k++) yield [this.keyList[k]!, this.run(k)];
  }

  override [Symbol.iterator](): MapIterator<[number, number[]]> {
    return this.entries();
  }

  override forEach(fn: (value: number[], key: number, map: Map<number, number[]>) => void): void {
    for (let k = 0; k < this.keyList.length; k++) fn(this.run(k), this.keyList[k]!, this);
  }

  override set(): this {
    throw new Error('The core’s references cannot be changed');
  }

  override delete(): boolean {
    throw new Error('The core’s references cannot be changed');
  }

  override clear(): void {
    throw new Error('The core’s references cannot be changed');
  }
}

/** The views of an arm64 pass, by number (`view_of` in crates/wasm/src/lib.rs). */
const ARM64 = {
  words: 0, mnemonicIds: 1, flags: 2, counts: 3,
  callers: 4, dataRefs: 7, slotCallers: 10, slotCallIndex: 13, slotCallSlot: 14, lengthAddr: 15, lengthValue: 16,
} as const;

/** What an arm64 pass hands over: everything copied out, the session closed. */
export interface Arm64Result {
  words: Uint32Array<ArrayBuffer>;
  mnemonicIds: Uint16Array<ArrayBuffer>;
  flags: Uint8Array<ArrayBuffer>;
  mnemonics: string[];
  counts: number[];
  callers: RefMap;
  dataRefs: RefMap;
  slotCallers: RefMap;
  /** Instruction index → the import slot it calls through. */
  slotCalls: Map<number, number>;
  /** String address → the length Rust code gives it. */
  lengthAt: Map<number, number>;
}

/**
 * The pass over every instruction of an arm64 program (crates/core/src/arm64/pass.rs).
 * `ranges` are the code sections by address: address, file offset, instruction count.
 */
export class Arm64Pass {
  private constructor(
    private readonly engine: Engine,
    private readonly handle: number,
  ) {}

  /**
   * The pass over a program the core reads itself (crates/core/src/native): its container read
   * again from the file, the image built, and after the pass (`analyse`) its functions, strings
   * and stubs found.
   */
  static native(engine: Engine, source: NativeSource): Arm64Pass {
    return new Arm64Pass(engine, openNative(engine, source, 0));
  }

  /** Decodes up to `budget` instructions more; true once the pass is over. */
  step(budget: number): boolean {
    return this.engine.call(() => this.engine.x.arm64_step(this.handle, budget)) === 1;
  }

  get done(): number {
    return this.engine.x.arm64_done(this.handle);
  }

  /** Runs the analysis after the pass (which must be over), copies the results out and closes the session. `addrOf` turns an instruction index into its address. */
  take(addrOf: (index: number) => number): Arm64Result & { native: NativeFound } {
    const e = this.engine;
    const h = this.handle;
    const native = nativeFound(e, h);
    const mnemonicText = e.out(e.call(() => e.x.arm64_mnemonics(h)));
    const refs = (id: number) => new RefMap(e.copy(h, id, Float64Array), e.copy(h, id + 1, Uint32Array), e.copy(h, id + 2, Uint32Array), addrOf);
    const pairs = (keys: Float64Array | Uint32Array, values: Float64Array | Uint32Array) => {
      const map = new Map<number, number>();
      for (let i = 0; i < keys.length; i++) map.set(keys[i]!, values[i]!);
      return map;
    };
    const result: Arm64Result = {
      words: e.copy(h, ARM64.words, Uint32Array),
      mnemonicIds: e.copy(h, ARM64.mnemonicIds, Uint16Array),
      flags: e.copy(h, ARM64.flags, Uint8Array),
      mnemonics: mnemonicText ? mnemonicText.split('\n') : [],
      counts: [...e.copy(h, ARM64.counts, Uint32Array)],
      callers: refs(ARM64.callers),
      dataRefs: refs(ARM64.dataRefs),
      slotCallers: refs(ARM64.slotCallers),
      slotCalls: pairs(e.copy(h, ARM64.slotCallIndex, Uint32Array), e.copy(h, ARM64.slotCallSlot, Float64Array)),
      lengthAt: pairs(e.copy(h, ARM64.lengthAddr, Float64Array), e.copy(h, ARM64.lengthValue, Uint32Array)),
    };
    e.x.close(h);
    return { ...result, native };
  }
}

/* ------------------------------------------------------------------ *
 * Native programs: the core reads the file, builds the image, finds the functions
 * ------------------------------------------------------------------ */

/** The file an image was read from (`Image.source`). */
export interface NativeSource {
  container: 'macho' | 'elf' | 'pe';
  file: Uint8Array;
  view?: 'arm' | 'x64';
}

/** What the analysis after a native pass found (`native_text` in crates/wasm/src/native.rs). */
export interface NativeFound {
  /** address, first, count, name, full, raw, kind, language */
  functions: [number, number, number, string, string, string | null, 'export' | 'symbol' | 'import' | 'entry' | 'anonymous', string | null][];
  /** address, text, section, NUL-terminated */
  strings: [number, string, string, number][];
  /** The stubs it named: address, name. */
  stubs: [number, string][];
}

/** Opens a native session: the file goes in (the core keeps it), the pass of `arch` (0 arm64) is ready to step. */
function openNative(engine: Engine, source: NativeSource, arch: number): number {
  const container = source.container === 'macho' ? 0 : source.container === 'elf' ? 1 : source.view === 'x64' ? 3 : 2;
  // The core takes the copy over: it is not freed here.
  const file = engine.put(source.file);
  const handle = engine.call(() => engine.x.native_open(file, source.file.length, container, arch));
  if (!handle) throw new CoreError('The core could not read the program');
  return handle;
}

/** Runs the analysis after a native pass and takes what it found. */
function nativeFound(engine: Engine, handle: number): NativeFound {
  engine.call(() => engine.x.native_finish(handle));
  const text = (what: number) => JSON.parse(engine.out(engine.call(() => engine.x.native_text(handle, what))));
  return { functions: text(0), strings: text(1), stubs: text(2) };
}

const utf8Encoder = new TextEncoder();

/** A JSON reviver that turns `{"big":"…"}` back into the BigInt it stands for. */
const bigints = (key: string, value: unknown): unknown =>
  key !== '' && value && typeof value === 'object' && typeof (value as { big?: unknown }).big === 'string' ? BigInt((value as { big: string }).big) : value;

/**
 * JSON from the core with its BigInts back. A reviver is called for every value — eight times the
 * cost of the parse on a big module — so it runs only when there is one: inside a JSON string the
 * quotes are escaped, so `{"big":` in the text can only be such an object.
 */
const withBigInts = (text: string): unknown => (text.includes('{"big":') ? JSON.parse(text, bigints) : JSON.parse(text));

/**
 * A map from instruction index to an address, as the core hands such maps over: the indices
 * ascending beside their values. Read like the `Map<number, number>` the rest of the code expects.
 */
export class PairMap extends Map<number, number> {
  constructor(
    private readonly keyList: Uint32Array,
    private readonly valueList: Float64Array,
  ) {
    super();
  }

  private find(key: number): number {
    const keys = this.keyList;
    let lo = 0;
    let hi = keys.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const at = keys[mid]!;
      if (at === key) return mid;
      if (at < key) lo = mid + 1;
      else hi = mid - 1;
    }
    return -1;
  }

  override get(key: number): number | undefined {
    const k = this.find(key);
    return k < 0 ? undefined : this.valueList[k];
  }

  override has(key: number): boolean {
    return this.find(key) >= 0;
  }

  override get size(): number {
    return this.keyList.length;
  }

  override *keys(): MapIterator<number> {
    for (let k = 0; k < this.keyList.length; k++) yield this.keyList[k]!;
  }

  override *values(): MapIterator<number> {
    for (let k = 0; k < this.keyList.length; k++) yield this.valueList[k]!;
  }

  override *entries(): MapIterator<[number, number]> {
    for (let k = 0; k < this.keyList.length; k++) yield [this.keyList[k]!, this.valueList[k]!];
  }

  override [Symbol.iterator](): MapIterator<[number, number]> {
    return this.entries();
  }

  override forEach(fn: (value: number, key: number, map: Map<number, number>) => void): void {
    for (let k = 0; k < this.keyList.length; k++) fn(this.valueList[k]!, this.keyList[k]!, this);
  }

  override set(): this {
    throw new Error('The core’s results cannot be changed');
  }

  override delete(): boolean {
    throw new Error('The core’s results cannot be changed');
  }

  override clear(): void {
    throw new Error('The core’s results cannot be changed');
  }
}

/** Switch tables as the core hands them over: instruction → the addresses of its cases. */
export class TableMap extends Map<number, number[]> {
  constructor(
    private readonly index: Uint32Array,
    private readonly starts: Uint32Array,
    private readonly targets: Float64Array,
  ) {
    super();
  }

  private find(key: number): number {
    let lo = 0;
    let hi = this.index.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const at = this.index[mid]!;
      if (at === key) return mid;
      if (at < key) lo = mid + 1;
      else hi = mid - 1;
    }
    return -1;
  }

  private run(k: number): number[] {
    return Array.from(this.targets.subarray(this.starts[k]!, this.starts[k + 1]!));
  }

  override get(key: number): number[] | undefined {
    const k = this.find(key);
    return k < 0 ? undefined : this.run(k);
  }

  override has(key: number): boolean {
    return this.find(key) >= 0;
  }

  override get size(): number {
    return this.index.length;
  }

  override *keys(): MapIterator<number> {
    for (let k = 0; k < this.index.length; k++) yield this.index[k]!;
  }

  override *values(): MapIterator<number[]> {
    for (let k = 0; k < this.index.length; k++) yield this.run(k);
  }

  override *entries(): MapIterator<[number, number[]]> {
    for (let k = 0; k < this.index.length; k++) yield [this.index[k]!, this.run(k)];
  }

  override [Symbol.iterator](): MapIterator<[number, number[]]> {
    return this.entries();
  }

  override forEach(fn: (value: number[], key: number, map: Map<number, number[]>) => void): void {
    for (let k = 0; k < this.index.length; k++) fn(this.run(k), this.index[k]!, this);
  }

  override set(): this {
    throw new Error('The core’s results cannot be changed');
  }

  override delete(): boolean {
    throw new Error('The core’s results cannot be changed');
  }

  override clear(): void {
    throw new Error('The core’s results cannot be changed');
  }
}

/** The views of an x86 pass, by number (`view_of` in crates/wasm/src/lib.rs). */
const X86 = {
  offs: 0, lens: 1, kinds: 2, mnemonicIds: 3, flags: 4, counts: 5, ranges: 6,
  callers: 7, dataRefs: 10, slotCallers: 13, tableIndex: 16, tableStarts: 17, tableTargets: 18,
  addressIndex: 19, addressValue: 20, codeIndex: 21, codeValue: 22, targetIndex: 23, targetValue: 24,
} as const;

/** What the analysis of an x86 program is given besides the image (`X86Input` in crates/core/src/x86_pass.rs). */

export interface X86Result {
  offs: Uint32Array<ArrayBuffer>;
  lens: Uint8Array<ArrayBuffer>;
  kinds: Uint8Array<ArrayBuffer>;
  mnemonicIds: Uint16Array<ArrayBuffer>;
  flags: Uint8Array<ArrayBuffer>;
  mnemonics: string[];
  counts: number[];
  /** Section index (in the image), first instruction, count: one per code section. */
  ranges: { section: number; first: number; count: number }[];
  callers: RefMap;
  dataRefs: RefMap;
  slotCallers: RefMap;
  tables: TableMap;
  addressAt: PairMap;
  codeAt: PairMap;
  /** Instruction → where its relative branch or call goes. */
  targets: PairMap;
}

/** The analysis of an x86 program in the core (crates/core/src/x86_pass.rs): the code laid out at once, then the pass in steps. */
export class X86Pass {
  private constructor(
    private readonly engine: Engine,
    private readonly handle: number,
  ) {}

  /** The pass over a program the core reads itself (crates/core/src/native), laid out at once, then stepped. */
  static native(engine: Engine, source: NativeSource): X86Pass {
    return new X86Pass(engine, openNative(engine, source, 1));
  }

  step(budget: number): boolean {
    return this.engine.call(() => this.engine.x.x86_step(this.handle, budget)) === 1;
  }

  get done(): number {
    return this.engine.x.arm64_done(this.handle);
  }

  get total(): number {
    return this.engine.x.arm64_total(this.handle);
  }

  /** Copies the results out and closes the session. `addrOf` turns an instruction index into its address. */
  take(addrOf: (index: number) => number): X86Result & { native: NativeFound } {
    const e = this.engine;
    const h = this.handle;
    const native = nativeFound(e, h);
    const mnemonicText = e.out(e.call(() => e.x.arm64_mnemonics(h)));
    const refs = (id: number) => new RefMap(e.copy(h, id, Float64Array), e.copy(h, id + 1, Uint32Array), e.copy(h, id + 2, Uint32Array), addrOf);
    const pairs = (index: number, value: number) => new PairMap(e.copy(h, index, Uint32Array), e.copy(h, value, Float64Array));
    const r = e.copy(h, X86.ranges, Uint32Array);
    const ranges: X86Result['ranges'] = [];
    for (let k = 0; k + 2 < r.length; k += 3) ranges.push({ section: r[k]!, first: r[k + 1]!, count: r[k + 2]! });
    const result: X86Result = {
      offs: e.copy(h, X86.offs, Uint32Array),
      lens: e.copy(h, X86.lens, Uint8Array),
      kinds: e.copy(h, X86.kinds, Uint8Array),
      mnemonicIds: e.copy(h, X86.mnemonicIds, Uint16Array),
      flags: e.copy(h, X86.flags, Uint8Array),
      mnemonics: mnemonicText ? mnemonicText.split('\n') : [],
      counts: [...e.copy(h, X86.counts, Uint32Array)],
      ranges,
      callers: refs(X86.callers),
      dataRefs: refs(X86.dataRefs),
      slotCallers: refs(X86.slotCallers),
      tables: new TableMap(e.copy(h, X86.tableIndex, Uint32Array), e.copy(h, X86.tableStarts, Uint32Array), e.copy(h, X86.tableTargets, Float64Array)),
      addressAt: pairs(X86.addressIndex, X86.addressValue),
      codeAt: pairs(X86.codeIndex, X86.codeValue),
      targets: pairs(X86.targetIndex, X86.targetValue),
    };
    e.x.close(h);
    return { ...result, native };
  }
}

/** The views of an AArch32 pass, by number (`view_of` in crates/wasm/src/lib.rs). */
const ARM32 = {
  addrs: 0, words: 1, kinds: 2, its: 3, mnemonicIds: 4, flags: 5, counts: 6, ranges: 7,
  callers: 8, dataRefs: 11, slotCallers: 14, tableIndex: 17, tableStarts: 18, tableTargets: 19,
  addressIndex: 20, addressValue: 21, slotIndex: 22, slotValue: 23, targetIndex: 24, targetValue: 25,
} as const;


export interface Arm32Result {
  mapped: boolean;
  addrs: Uint32Array<ArrayBuffer>;
  words: Uint32Array<ArrayBuffer>;
  kinds: Uint8Array<ArrayBuffer>;
  its: Int8Array<ArrayBuffer>;
  mnemonicIds: Uint16Array<ArrayBuffer>;
  flags: Uint8Array<ArrayBuffer>;
  mnemonics: string[];
  counts: number[];
  ranges: { section: number; first: number; count: number }[];
  callers: RefMap;
  dataRefs: RefMap;
  slotCallers: RefMap;
  slotCalls: PairMap;
  tables: TableMap;
  addressAt: PairMap;
  /** Calls and branches with a target: the instruction → where it goes. */
  targets: PairMap;
}


/** The analysis of AArch32 code in the core (crates/core/src/arm32_pass.rs): the layout settled at once, then the pass in steps. */
export class Arm32Pass {
  private constructor(
    private readonly engine: Engine,
    private readonly handle: number,
  ) {}

  /** The pass over a program the core reads itself (crates/core/src/native): each instruction set settled, then stepped. */
  static native(engine: Engine, source: NativeSource): Arm32Pass {
    return new Arm32Pass(engine, openNative(engine, source, 2));
  }

  step(budget: number): boolean {
    return this.engine.call(() => this.engine.x.arm32_step(this.handle, budget)) === 1;
  }

  get done(): number {
    return this.engine.x.arm64_done(this.handle);
  }

  get total(): number {
    return this.engine.x.arm64_total(this.handle);
  }

  take(addrOf: (index: number) => number): Arm32Result & { native: NativeFound } {
    const e = this.engine;
    const h = this.handle;
    const native = nativeFound(e, h);
    const mnemonicText = e.out(e.call(() => e.x.arm64_mnemonics(h)));
    const refs = (id: number) => new RefMap(e.copy(h, id, Float64Array), e.copy(h, id + 1, Uint32Array), e.copy(h, id + 2, Uint32Array), addrOf);
    const pairs = (index: number, value: number) => new PairMap(e.copy(h, index, Uint32Array), e.copy(h, value, Float64Array));
    const r = e.copy(h, ARM32.ranges, Uint32Array);
    const ranges: Arm32Result['ranges'] = [];
    for (let k = 0; k + 2 < r.length; k += 3) ranges.push({ section: r[k]!, first: r[k + 1]!, count: r[k + 2]! });
    const its = e.copy(h, ARM32.its, Uint8Array);
    const result: Arm32Result = {
      mapped: e.x.arm32_mapped(h) === 1,
      addrs: e.copy(h, ARM32.addrs, Uint32Array),
      words: e.copy(h, ARM32.words, Uint32Array),
      kinds: e.copy(h, ARM32.kinds, Uint8Array),
      its: new Int8Array(its.buffer, its.byteOffset, its.length),
      mnemonicIds: e.copy(h, ARM32.mnemonicIds, Uint16Array),
      flags: e.copy(h, ARM32.flags, Uint8Array),
      mnemonics: mnemonicText ? mnemonicText.split('\n') : [],
      counts: [...e.copy(h, ARM32.counts, Uint32Array)],
      ranges,
      callers: refs(ARM32.callers),
      dataRefs: refs(ARM32.dataRefs),
      slotCallers: refs(ARM32.slotCallers),
      slotCalls: pairs(ARM32.slotIndex, ARM32.slotValue),
      tables: new TableMap(e.copy(h, ARM32.tableIndex, Uint32Array), e.copy(h, ARM32.tableStarts, Uint32Array), e.copy(h, ARM32.tableTargets, Float64Array)),
      addressAt: pairs(ARM32.addressIndex, ARM32.addressValue),
      targets: pairs(ARM32.targetIndex, ARM32.targetValue),
    };
    e.x.close(h);
    return { ...result, native };
  }
}

/** The views of a JVM session, by number (`view_of` in crates/wasm/src/lib.rs). */
export const JVM_VIEW = {
  offsets: 0, mnemonicIds: 1, flags: 2, counts: 3, callers: 4, dataRefs: 7, fieldRefs: 10,
  targetIndex: 13, targetStarts: 14, targetValues: 15, targetLists: 16, bodies: 17, ranges: 18, fieldStarts: 19,
  calleeKeys: 20, calleeValues: 21, fieldKeys: 22, fieldValues: 23,
} as const;

/** The texts of a JVM session, by number (`jvm_text` in crates/wasm/src/jvm.rs). */
export const JVM_TEXT = { mnemonics: 0, functions: 1, imports: 2, strings: 3, classes: 4, container: 5, meta: 7 } as const;

/** Why the core could not open a file as Java classes; `text` is the reader's own words. */
export type JvmOpenError = { error: 'notJava' | 'noClasses' } | { error: 'zip' | 'class'; text: string };

export class JvmOpenFailed extends Error {
  constructor(readonly reason: JvmOpenError) {
    super(reason.error);
  }
}

/**
 * Java classes read (and, with `analyse`, analysed) in the core (crates/core/src/jvm/program.rs).
 * The session holds the classes for as long as it is open, and hands over a class's bytes when
 * asked: the page parses only the classes it shows.
 */
export class JvmSession {
  readonly handle: number;

  constructor(
    readonly engine: Engine,
    bytes: Uint8Array,
    analyse: boolean,
  ) {
    // The core takes the copy over: it is not freed here.
    const ptr = engine.put(bytes);
    const handle = engine.call(() => engine.x.jvm_open(ptr, bytes.length, analyse ? 1 : 0));
    if (!handle) throw new JvmOpenFailed(JSON.parse(engine.out(engine.x.jvm_open_error())) as JvmOpenError);
    this.handle = handle;
  }

  /** Works on for about `budget` instructions; true once the work is done. */
  step(budget: number): boolean {
    return this.engine.call(() => this.engine.x.jvm_step(this.handle, budget)) === 1;
  }

  get done(): number {
    return this.engine.x.jvm_done(this.handle);
  }

  get total(): number {
    return this.engine.x.jvm_total(this.handle);
  }

  text(what: number): string {
    return this.engine.out(this.engine.call(() => this.engine.x.jvm_text(this.handle, what)));
  }

  json<T>(what: number): T {
    return JSON.parse(this.text(what)) as T;
  }

  copy<T extends TypedArray>(id: number, Kind: TypedArrayKind<T>): T {
    return this.engine.copy(this.handle, id, Kind);
  }

  refs(id: number, addrOf: (index: number) => number): RefMap {
    return new RefMap(this.copy(id, Float64Array), this.copy(id + 1, Uint32Array), this.copy(id + 2, Uint32Array), addrOf);
  }

  close(): void {
    this.engine.x.close(this.handle);
  }
}

/** The views of a WebAssembly session, by number (`view` in crates/wasm/src/webassembly.rs). */
export const WASM_VIEW = {
  offsets: 0, depth: 1, mnemonicIds: 2, flags: 3, counts: 4, callers: 5, dataRefs: 8, refFuncs: 11, globalRefs: 14, indirect: 17,
  targetIndex: 20, targetStarts: 21, targetValues: 22, valueBranches: 23, lengthAddr: 24, lengthValue: 25, bodies: 26, lineAddrs: 27, lineRows: 28,
} as const;

/** The texts of a WebAssembly session, by number (`wasm_text` in crates/wasm/src/webassembly.rs). */
export const WASM_TEXT = { mnemonics: 0, bodies: 1, imports: 2, strings: 3, segments: 4, meta: 5 } as const;

/** The views of a .NET session, by number (`view` in crates/wasm/src/cil.rs). */
export const CIL_VIEW = {
  offsets: 0, mnemonicIds: 1, flags: 2, counts: 3, callers: 4, dataRefs: 7, fieldRefs: 10, typeRefs: 13,
  targetIndex: 16, targetStarts: 17, targetValues: 18, regions: 19, functions: 20,
} as const;

/** The texts of a .NET session, by number (`cil_text` in crates/wasm/src/cil.rs). */
export const CIL_TEXT = { mnemonics: 0, functions: 1, imports: 2, pinvokes: 3, ranges: 4, meta: 5, strings: 6 } as const;

/**
 * The pass over a whole bytecode program in the core — a WebAssembly module
 * (crates/core/src/wasm/program.rs) or a .NET assembly (crates/core/src/cil/program.rs) — run in
 * steps; its results are copied out once and the session closed.
 */
export class PassSession {
  private constructor(
    readonly engine: Engine,
    readonly handle: number,
    private readonly kind: 'wasm' | 'cil',
  ) {}

  /** A WebAssembly module. */
  static wasm(engine: Engine, bytes: Uint8Array): PassSession {
    // The core takes the copy over: it is not freed here.
    const ptr = engine.put(bytes);
    return PassSession.opened(engine, engine.call(() => engine.x.wasm_open(ptr, bytes.length)), 'wasm');
  }

  /** A .NET assembly: the PE file, its sections (RVA, virtual size, raw size, raw offset) and the RVA of its CLR directory. */
  static cil(engine: Engine, bytes: Uint8Array, sections: { rva: number; virtualSize: number; rawSize: number; rawOffset: number }[], clr: number | undefined): PassSession {
    const ptr = engine.put(bytes);
    const quads = engine.putF64(sections.flatMap((s) => [s.rva, s.virtualSize, s.rawSize, s.rawOffset]));
    try {
      return PassSession.opened(engine, engine.call(() => engine.x.cil_open(ptr, bytes.length, quads.ptr, sections.length, clr ?? -1)), 'cil');
    } finally {
      engine.free(quads.ptr, quads.bytes);
    }
  }

  private static opened(engine: Engine, handle: number, kind: 'wasm' | 'cil'): PassSession {
    if (!handle) throw new CoreError(`The core could not read the ${kind === 'wasm' ? 'module' : 'assembly'}`);
    return new PassSession(engine, handle, kind);
  }

  /** Works on for about `budget` instructions; true once the work is done. */
  step(budget: number): boolean {
    return this.engine.call(() => this.engine.x[`${this.kind}_step`](this.handle, budget)) === 1;
  }

  get done(): number {
    return this.engine.x[`${this.kind}_done`](this.handle);
  }

  get total(): number {
    return this.engine.x[`${this.kind}_total`](this.handle);
  }

  text(what: number): string {
    return this.engine.out(this.engine.call(() => this.engine.x[`${this.kind}_text`](this.handle, what)));
  }

  json<T>(what: number): T {
    return JSON.parse(this.text(what)) as T;
  }

  copy<T extends TypedArray>(id: number, Kind: TypedArrayKind<T>): T {
    return this.engine.copy(this.handle, id, Kind);
  }

  refs(id: number, addrOf: (index: number) => number): RefMap {
    return new RefMap(this.copy(id, Float64Array), this.copy(id + 1, Uint32Array), this.copy(id + 2, Uint32Array), addrOf);
  }

  close(): void {
    this.engine.x.close(this.handle);
  }
}
