# Arm, x86, WebAssembly, .NET and Java Disassembler — a macOS, iOS, Windows, Linux or Android binary, a wasm module, a .NET assembly or a Java JAR, taken apart in one HTML file

<!-- languages -->
<h3 align="center">
<b>🇬🇧 English</b> ·
<a href="docs/readme/README.ru.md">🇷🇺 Русский</a>
</h3>
<!-- /languages -->

Open a macOS program — an app's executable, a `.dylib`, a command-line tool, for Apple Silicon
or Intel, 64-bit or old i386 —, an iOS app (the whole `.ipa`, arm64 or old armv7), a Windows `.exe` or `.dll` for x86-64, i386, arm64 (ARM64EC and ARM64X too) or 32-bit Arm, an Android native library for
arm64-v8a, armeabi-v7a, x86_64 or x86 (a `.so`, or the whole `.apk`), a Linux program or library
for x86-64, i386, arm64 or 32-bit Arm, a WebAssembly module, a .NET assembly — the CIL of C#, F#
or Visual Basic —, or Java bytecode — a `.class` or a `.jar` of Java, Kotlin or Scala —, and see
every instruction of it: decoded, explained, counted, and — for arm64, x86-64, WebAssembly, .NET and Java — written
either as assembly or as [HLA64](https://github.com/marketkernel/html-hlaa64), an assembler with
syntactic sugar for ARM64, x64 and WebAssembly.

The whole tool is one self-contained page, `build/disassembler.html`. It works from disk,
offline, in any modern browser. **Nothing is uploaded**: the file is read by the page, and the
page's Content-Security-Policy forbids it any network access at all.

**Online version: <https://disasm.marketkernel.com>** — the same page as a PWA (Progressive Web
App). Once opened, it works offline: the page is kept in the browser and opens with no
connection, and programs are still read from the disk, never uploaded. It can be installed into
the system and then runs as a separate app, with its own window and icon: on a computer, in
Chrome, Edge and Arc, the install button in the address bar; on iOS, Share → Add to Home Screen.

**Or download the file**: every [release](https://github.com/MarketKernel/html-disasm/releases)
has `disassembler-<version>.html` — the whole disassembler in one file, to keep on disk and open
in a browser with no network at all — and `SHA256SUMS.txt` to check it against.

Source: <https://github.com/MarketKernel/html-disasm>.

```
address      assembly                              HLA64
1003a5d50    adrp   x8, 0x100391000                x8 = &sub_100391ed8
1003a5d54    add    x8, x8, #0xed8
1003a5d6c    bl     std::rt::lang_start_internal   `std::rt::lang_start_internal`()
1004cb2a8    cmp    x8, #0x1                       if x8 != 1 { goto L1004cb2b8 }
1004cb2ac    b.ne   L1004cb2b8
1004cb364    adrp   x8, 0x100a4b000                x8 = "{invalid syntax}"
1004cb368    add    x8, x8, #0xfe0
1004cb378    cmp    w10, #0x0                      x1 = w10 != 0 ? x9 : x8
1004cb37c    csel   x1, x9, x8, ne
10003171c    ldaddl x9, x8, [x8]                   x8 = atomic_add(u64[x8], x9, release)
```

The same program, `hello.c`, built for WebAssembly by Emscripten:

The Android build of it for armeabi-v7a, Thumb-2 with one file in A32, from the APK as it is
(stripped: which bytes are T32, A32 and data is worked out from the code):

```
address  assembly
8fa      ldr     r1, [pc, #0x78]             ; "hello"
8fc      add     r1, pc                      ; "hello"
902      stm.w   sp, {r4, r5, r10}
90c      blx     __android_log_print
916      cbz     r0, L960
934      it      ne
936      movne   r1, r2
a20      cmp     r1, #1                      (A32, arm.c)
a24      poplt   {r11, pc}
```

```
offset  WebAssembly                     HLA64
3f0     i32.const 0                     atomic_add(u32[0x770], l0, seq_cst)
3f2     local.get 0
3f4     i32.atomic.rmw.add offset=1904
3fc     drop
3fd     i32.const 1200                  l3 = sum(0x4b0, 8)
403     i32.const 8
405     call $sum
40b     local.set 3
43b     i32.const 1152                  __small_printf("Hello, world! sum=%ld avg=%.2f kind=%s\n", l2)
441     local.get 2
443     call $__small_printf
449     drop
453     local.get 1                     if strcmp(i32[l1 + 4], "--help") { goto L473 }
455     i32.load offset=4
458     i32.const 1079
45e     call $strcmp
464     br_if 0
```

## Using it

1. `./build.sh open` (or `npm install && npm run build`, then open `build/disassembler.html`); it
   needs Node 22+ and Rust with the WebAssembly target (`rustup target add wasm32-unknown-unknown`).
2. Click **Open a program** or drop a file on the page. An app's program is inside its bundle:
   `Name.app/Contents/MacOS/Name` (in the Finder: Show Package Contents). Universal files open at
   their arm64 slice; the **Mach-O** page opens the others (x86_64, and the i386 or armv7 slices
   of old programs). An Android library is a `.so` file; an `.apk` (or `.aab`, or a bundle of
   split APKs: `.apks`, `.xapk`) opens a list of the libraries inside it by ABI, and the one
   picked is taken out and opened. An iOS `.ipa` (or a zipped `.app`) lists the app's executable,
   its frameworks and extensions in the same way. A Windows `.exe` or `.dll` opens as it is — a .NET assembly too, its IL written as ildasm writes it. A Java `.class` or
   `.jar` (or `.war`, `.jmod`, `.aar`) opens as one program, all its classes, the bytecode written as javap writes it. A `.wasm`
   file is recognised by its signature; a web page's module can be saved from the Network tab of
   the browser's developer tools.
3. The page decodes every instruction (2 million take about a second, a 4-million-instruction
   module a second and a half) and opens at `main`.

| Where | What |
| --- | --- |
| **Code** | The listing. **Assembly / HLA64** at the top switches the notation (keys **A** / **H**). Names are links: click one to follow a branch or a call, **Alt ←** to come back. Arrows in the margin show the branches within a function. The left panel lists the functions; the right one explains whatever is selected. Drag the border of either panel to widen it (double-click for the usual width). |
| **Statistics** | Every mnemonic with how often the program uses it, most frequent first, as a table with bars; the same by kind of work. **Copy as CSV** takes the table. |
| **Strings** | C strings, and the Rust string literals the code points at. Double-click goes to the first use. |
| **Imports and exports** | The libraries and the functions taken from them, with how many places call each, and the symbols the program exports — from the Mach-O export trie or the ELF dynamic symbols — with their addresses, kinds and the calls to them from its own code. For a module: what it takes from each host module and what it exports. For a .NET assembly, **References**: the assemblies it is built against, the members of theirs it uses, P/Invokes, forwarded types. For Java, **References**: the packages and classes of other libraries its code uses, and their members. |
| **Mach-O** | Header, segments and sections, load commands, the build, the code signature and entitlements, the Objective-C classes; for a program from an `.ipa`, its bundle, version and provisioning profile. For a Windows program, **PE**: the headers, the Windows version and subsystem, the linker and the PDB it points at, the security flags, the needed DLLs (delay-loaded ones marked), sections and data directories. For an Android library, **ELF**: the header, the API level and NDK, the needed libraries, the Arm build attributes, segments, sections, relocations and the dynamic section. For a module, **Module**: every section, memory, tables, globals, types, data and element segments, custom sections, producers, features, DWARF source files. For a .NET assembly, **Assembly**: name and version, target framework, runtime, CLI flags, strong name, ReadyToRun, metadata streams and tables, resources, types. For Java, **Classes**: the JAR's manifest, the class file versions, the module, the classes and the other files in it. |
| **Reference** | All 1,194 A64 instructions — or, with 32-bit Arm code open, all 485 AArch32 ones; with x86 code, 1,805 x86 mnemonics; with a module, all 572 WebAssembly instructions; with a .NET assembly, all 219 CIL ones; with Java bytecode, the 213 JVM mnemonics javap prints — with a description of each, its forms and syntax, a link to Arm's documentation, the WebAssembly or the JVM specification, and where the open program uses it. Also the HLA64 vocabulary. |

**⌘K** (Ctrl K) searches functions, imports, strings, instructions and addresses (`0x1000…`);
**G** jumps to an address. In the listing, **↑ ↓ PgUp PgDn** move the selection and **Enter** follows it.

## The instruction catalogue

`src/data/arm64-instructions.json` holds every AArch64 instruction outside SVE and SME —
1,194 mnemonics — each with a short name, a plain-English description, the operation as a
formula, the flags it reads or sets, its category, and its forms with assembler syntax and a
link to the page in Arm's documentation.

The list of instructions, their forms and syntax come from Arm's machine-readable
specification, the *A64 ISA XML for A-profile Architecture*. Arm's own text is under a notice
that forbids copying it, so none of it is: the descriptions are written for this project, and
each form links to Arm's page for the authoritative text. `tests/data.mjs` checks that every
entry is complete and that no description reads like the specification.

`src/data/wasm-instructions.json` does the same for WebAssembly: 572 instructions, each with a
name, a description, the operation and a category; the opcodes, immediates and stack signatures
come from the decoder's table (`src/core/wasm/opcodes.ts`), and each form links to its part of
the WebAssembly specification (or of the threads, legacy exceptions and wide-arithmetic
proposals). `src/data/wasm-instructions.ru.json` has the Russian texts.

`src/data/cil-instructions.json` holds the 219 CIL instructions: a name, a description and the
operation, in our own words; the opcodes, operands and stack behaviour come from the decoder's
table (`src/core/cil/opcodes.ts`), and each links to its page of `System.Reflection.Emit.OpCodes`
on Microsoft Learn (ECMA-335 for `no.`, which has none). `src/data/cil-instructions.ru.json` has
the Russian texts.

`src/data/jvm-instructions.json` holds the 213 mnemonics javap prints for the JVM's 202 opcodes
(the wide forms, `iload_w` and the like, each an entry): a name, a description and the operation
in our own words; the opcodes, operands and stack behaviour come from the decoder's table
(`src/core/jvm/opcodes.ts`), and each links to its page in chapter 6 of the Java Virtual Machine
Specification. `src/data/jvm-instructions.ru.json` has the Russian texts.

To refresh the forms from a newer release of the XML (the descriptions stay):

```sh
node tools/arm-index.mjs ~/Downloads/ISA_A64_xml_A_profile-2025-12
node tools/arm32-index.mjs ~/Downloads/ISA_AArch32_xml_A_profile-2025-12
```

`src/data/arm32-instructions.json` is the same for AArch32 — A32 and T32, base, floating point,
Advanced SIMD, crypto and the later extensions (dot product, BF16, Int8 matrix multiply): 485
mnemonics, every one in Arm's *AArch32 ISA XML for A-profile Architecture* plus the two LLVM
prints that have no page of their own (`trap`, `hint`). Each form says which instruction sets
have it (A32, T32) and links to Arm's page; the descriptions are our own, in English and Russian
(`src/data/arm32-instructions.ru.json`). A printed mnemonic finds its entry without its
condition and qualifiers: `addeq` is `add`, `vaddeq.f32` `vadd`, `bls` `b`, `itte` `it`.

## HLA64

HLA64 is an assembler, not a new language: its programs are ordinary instructions, with sugar
for what is obvious — `x0 = [x1 + 8]`, `if x8 == 0 { goto L… }`, `push x29, x30`, `f()`. The
HLA64 view writes each instruction with those words where one fits and leaves it as an
instruction where none does, which HLA64 accepts as it is. Two neighbours that only make sense
together become one line: a compare and the branch or select that tests its flags, and an
`adrp` with the `add` or load that completes an address — which then shows as the string or
symbol it points at.

Disassembled code needs a few words HLA64 does not have yet: unsigned comparisons (`<u`, `>=u`),
`udiv()`, `umulh()`, atomics (`atomic_add(u64[x0], x1, release)`, `cas(…)`), `load_acquire`,
names that are not identifiers (`` `core::fmt::Formatter::pad`() ``), Objective-C's constant
strings (`x2 = @"Hello, %@!"`) and a few more. They are
in `src/data/hla64-words.json` with the language's own words, marked `"new"`, and underlined in
the listing; hovering one explains it. Each word says which views write it (`targets`) and the
instructions it stands for on each; the WebAssembly view adds a few of its own — locals (`l3`),
an assignment used as a value (`(l3 = x)`), calls through a table (`table[i](a, b)`),
conversions (`i32(x)`, `f64u(x)`), instructions as functions (`i32x4.add(a, b)`).

The x86-64 view (`crates/core/src/x86/hla.rs`) writes the same words over x86's registers — `rax =
[rbp - 0x28]`, `eax = u8[rdi + rcx]`, `rcx += rdx`, `if edi >u 7 { goto L… }`, `printf()`,
`atomic_add(u64[&counter], r14, seq_cst)` for a `lock add` — and keeps the instruction wherever
the sugar would mean something else: an 8- or 16-bit register, a compare with memory, a jump on a
flag the sugar cannot name (`cmovl` after `sub`), anything on `float` in xmm (HLA64's xmm values
are doubles). HLA64's own `push` and `pop` keep a register in a frame slot on x64, so a real
`push rbx` is written as what it does (`rsp -= 8; [rsp] = rbx`), and an instruction HLA64 would
read as one of its words goes in `asm "…"`. There is no HLA64 view of i386 code: HLA64 has no
target for it.

The .NET view (`crates/core/src/cil/hla.rs`) works as the WebAssembly one does, over CIL's locals
(`V_0`), arguments, fields, calls and arrays — `V_1 = Program::Sum(V_0, i32(len(V_0)))`,
`Console::WriteLine("usage")`, `V_0 += i64(values[V_1])` — with words of its own marked new; see
[.NET (CIL)](#net-cil). So does the Java view (`crates/core/src/jvm/hla.rs`), over the JVM's locals
(`i`, `l3`), fields, calls and arrays — `sum = Hello::sum(values, len(values))`,
`p = new Point(3, 4)`, `System::out.println(concat("sum=", sum))`; see
[Java (JVM bytecode)](#java-jvm-bytecode).

## Android: arm64-v8a and armeabi-v7a

An Android library opens like a program, with the same pages; the **Mach-O** tab is **ELF**.
The file chip names the ABI (`arm64-v8a`, `armeabi-v7a`) and the oldest Android the library
runs on (`Android 7.0+`), from the note the NDK leaves in it; without the note, Bionic's symbol
versions (`LIBC`) still say Android, as glibc's say Linux. A Mach-O program shows its platform
the same way (`macOS 14.0+`).

- **ELF** (`crates/core/src/elf.rs`, in the core): 32- and 64-bit files, with or without section headers. The
  symbol tables, the needed libraries, and the symbol versions that say which library an import
  comes from (`strcmp@LIBC`); relocations in every form linkers write them — REL, RELA, RELR and
  Android's packed APS2 — which name the GOT slots; Android's note (API level, NDK), the build
  ID, BTI/PAC, the Arm build attributes; and the unwind tables (`.ARM.exidx`, `.eh_frame_hdr`)
  and init/fini arrays, which list where functions start even in a stripped library. PLT stubs
  are named after the slot they jump through — an import, or `name@plt` for the library's own
  exported function.
- **arm64-v8a** goes through the arm64 analysis of a Mach-O program, HLA64 view included.
- **armeabi-v7a** (`src/core/arm32/`) is two instruction sets in one section, with constants
  among the instructions. A library that kept its symbol table says which bytes are A32, T32 or
  data with mapping symbols. A stripped one — every library in an APK — does not, and the
  analysis works it out (`crates/core/src/arm32/pass.rs`, `crates/core/src/native/arm32.rs`): symbols, init pointers and the PLT give
  the set at their addresses; calls give it at their targets (`blx` switches, `bl` keeps) when
  the bytes there look like it; static functions the unwind table lists are judged from their
  prologue or by reading their first bytes both ways; the words PC-relative loads (and `adr`
  with a load after it) read, switch tables (`tbb`/`tbh`, A32 `add pc`/`ldr pc`) and the linker's
  padding between functions are data, shown as `.word`. On NDK's libc++, the ASan runtime and
  libomp, stripped, the result differs from their mapping symbols on 10, 43 and 4 of 180,000,
  176,000 and 157,000 instructions; on the Flutter engine 116 of 1.86 million words do not
  decode.
  `ldr rX, [pc, #…]` and the `add rX, pc` after it, `movw`/`movt`, `adr` and loads from GOT
  slots name the strings, globals and imports they make the address of; IT blocks condition
  the instructions after them; switches get their cases as branch targets.
- **Linux programs** for arm64 and armhf (glibc) go through the same analyses. In a stripped one
  `main` is what `_start` passes to `__libc_start_main`, made from `adr`, `adrp` + `add`, a
  literal or a GOT slot.
- **Decoder** (`a32.ts`, `thumb.ts`, `simd*.ts`): A32, T16 and T32 of Armv8.6-A AArch32 —
  integer, system and coprocessor instructions, VFP with FP16, Advanced SIMD, crypto, CRC, dot
  product, BF16, Int8 matrix multiply. It prints what llvm-objdump prints, IT blocks counted as
  LLVM counts them, and `tools/verify-arm32.mjs` checks it line by line: on 5 million random A32
  words, 4 million random T32 and Thumb streams, and the four real libraries above
  (660,000 instructions), it differs from llvm-objdump nowhere.
- There is no HLA64 view of 32-bit Arm code: HLA64 has no target for it.

## WebAssembly

A `.wasm` file opens like a program, with the same pages. Code addresses are offsets in the
file, as browsers' developer tools show them; data addresses are addresses in the module's
linear memory.

- **Decoder** (`crates/core/src/wasm/decode.rs`, in the core): every instruction of WebAssembly 3.0 — the MVP, sign
  extension, saturating conversions, bulk memory, reference types, multi-value, SIMD and
  relaxed SIMD, tail calls, exception handling (also the legacy `try`/`catch`), typed function
  references, GC, memory64 and multiple memories — plus the threads proposal's atomics and wide
  arithmetic: 572 mnemonics. It prints the text format exactly as `wasm-tools print` does, and
  `tools/verify-wasm.mjs` checks it line by line: 39 million instructions of 40 real modules
  (Go, Rust, C++ with relaxed SIMD, Emscripten side modules, esbuild, tesseract) and those of
  random modules with every proposal turned on, without a difference. The page asks the core
  for the instructions of the rows on screen.
- **Module** (`crates/core/src/wasm/module.rs`, in the core, handed to the page as JSON;
  `tools/diff-wasm-module.mjs` compares what the page reads with the TypeScript reader it
  replaced, damaged modules too): every section, including rec groups of GC types,
  element and data segments of all kinds, tags, and the custom sections tools leave: `name`
  (functions, locals, globals, data, types…), `producers`, `target_features`, `dylink.0`,
  `linking` and `reloc.*` of object files, `sourceMappingURL`, `build_id`; and the line tables
  of DWARF (`crates/core/src/wasm/dwarf.rs`), which put the source file and line beside the code.
- **Analysis** (`crates/core/src/wasm/program.rs`, in the core): functions named from the name section, the
  linking symbols, the exports and the imports (Rust and C++ names demangled); labels from the
  nesting of blocks, so a `br 1` has an address and an arrow; calls, and for `call_indirect`
  the functions of its type in the tables; the strings in data segments and the constants that
  point at them — also in passive segments that a threaded module's start function copies in
  with `memory.init`; the toolchain (Emscripten, wasm-bindgen, Go, WASI…). esbuild's 4.2
  million instructions are analysed in about 0.3 s, three to five times faster than by the
  TypeScript it replaced.
- **HLA64** (`crates/core/src/wasm/hla.rs`): HLA64 has a WebAssembly target, so the same view works.
  The stack machine's instructions are folded back into the statements they compute —
  `l3 = sum(0x4b0, 8)` for four instructions — evaluating the stack with expressions; a line
  means exactly what its instructions do, operands in the order they are computed. `select`
  becomes `c ? a : b` only when nothing in it has an effect, `br_table` a `switch` with its
  cases grouped, `if` with its condition `if c {`. `block`, `loop` and `end` stay instructions,
  since HLA64's own `loop { }` repeats and WebAssembly's does not; branches are `goto` to
  labels. Instructions without sugar of their own are written as functions of their operands
  (`i32x4.add(a, b)`). On every real module tried, every statement reads as one line.

## .NET (CIL)

A .NET assembly — a `.dll` or `.exe` with a CLR header, from C#, F#, Visual Basic or C++/CLI —
opens like any Windows program, with its IL as the code. An instruction's address is its RVA; the
listing writes it, as ildasm does, as the offset in its method (`IL_001f`).

```
IL_0007    ldstr      "--help"
IL_000c    call       bool [System.Runtime]System.String::op_Equality(string, string)
IL_0011    brfalse.s  IL_001f
IL_00a8    ldsfld     class [System.Runtime]System.Func`2<int32,int32> Hello.Program/'<>c'::'<>9__6_0'
IL_014a    call       !!0 Hello.Program::Largest<string>(class [System.Collections]System.Collections.Generic.List`1<!!0>)
```

- **Decoder** (`crates/core/src/cil/decode.rs` and `page.rs`, in the core): all 219 opcodes of ECMA-335 Partition III, prefixes included,
  printed as Microsoft's ildasm prints them, operands and all: methods and fields with their
  signatures and assemblies, generic instances, function pointers, quoted names (`'<>c'`,
  `'value'`), strings that are not plain ASCII as `bytearray (…)`, floating-point constants as C's
  `%g` writes them and NaNs and infinities as their bytes. Where ildasm has quirks — which
  generic parameters it names (`!T`) and which it numbers (`!0`), where it breaks a parameter
  list onto new lines (written here `, `, against a bare `,`) — the rules are its own, read from
  its source. `tools/verify-cil.mjs` compares the text the page shows with ildasm line by line: every method
  of the 172 assemblies of .NET 10's shared framework (2.7 million instructions,
  System.Private.CoreLib among them), of F#'s compiler and core library (1.9 million) and of 155
  assemblies of JetBrains Rider (8.6 million) — 13.3 million instructions without a difference.
  The page asks the core for the instructions of the rows on screen.
- **Metadata** (`crates/core/src/cil/metadata.rs`, `names.rs`, in the core): the CLI header, the
  metadata root and its streams (`#~` or `#-`, `#Strings`, `#US`, `#GUID`, `#Blob`), all 45
  tables, the method bodies with their tiny or fat headers and exception clauses, and the
  signatures of types, methods, fields and locals. What the page shows of them — a method's card
  and HLA64 header, the Assembly and References pages — is written there too (`page.rs`) when it
  is shown, and `tools/diff-cil-page.mjs` compares it with the TypeScript that read the metadata
  before.
- **Analysis** (`crates/core/src/cil/program.rs`, in the core, which reads the metadata and
  writes the names as well): every method with a body is a function, named
  `Namespace.Type::Method` and grouped by type; branches, switches and exception handlers make
  labels, and the try blocks and handlers are marked where they start; calls are counted for the
  methods here — through a MemberRef too, when its class is a generic one defined here — and for
  the members of other assemblies, which are the imports; the strings are those of `#US`; the
  target framework comes from `TargetFrameworkAttribute`, the entry point from the CLI header.
  FSharp.Compiler.Service (1.6 million instructions) is analysed in about 0.4 s, twice as fast as
  by the TypeScript it replaced.
- The **Assembly** page shows the manifest (name, version, culture, public key, MVID), the target
  framework and the runtime, the CLI flags, the strong name and ReadyToRun, the metadata streams
  and tables, the resources and the types; **References** shows the assemblies it is built
  against, the members of theirs its code uses, its P/Invokes and its forwarded types.
- **HLA64** (`crates/core/src/cil/hla.rs`): the same view as WebAssembly's — the stack machine's
  instructions folded back into the statements they compute: `V_1 = Program::Sum(V_0,
  i32(len(V_0)))` for six of them, `if len(args) == 0 { goto IL_001f }`, `V_0 += i64(values[V_1])`,
  `(&V_0).n = n`, `new List<string>()`. Locals are `V_n` and arguments go by their names; fields and
  methods are `obj.f` and `Type::f`, `Type::M(…)` for a call and `obj.M(…)` for a virtual one
  (callvirt), types by their short names with their generic arguments. A word is written only where
  it means exactly the instructions: every value carries whether it is an integer, a float, a
  reference or a pointer — from the signatures of the locals, arguments, fields and methods it
  comes from —, so `>u` is written only between integers, a branch on false is negated only where
  no NaN can make it wrong, `%` only between integers; a `dup` is folded only when it copies a
  variable or a constant, and no value crosses a label or the start of a handler. What has no word
  stays an instruction (`leave`, `endfinally`, the prefixes) or is written as a function of its
  operands (`add.ovf(a, b)`, `box<Kind>(x)`). On .NET 10's shared framework and F#'s libraries
  68% of the lines, 87% of the instructions, read as HLA64.

## Java (JVM bytecode)

A `.class` file, a `.jar` (or a `.war`, a JDK's `.jmod`, an Android library's `.aar`, whose
`classes.jar` is read) opens as one program: every class in it, written in Java, Kotlin, Scala or
anything else that compiles to the JVM. A class file has no addresses, so each method's code gets
a place of its own; the listing writes an instruction at its pc, as javap does, and what the
constant pool index names after `//`.

```
  8: ldc           #59    // String --help
 10: invokevirtual #61    // Method java/lang/String.equals:(Ljava/lang/Object;)Z
 13: ifeq          25
 67: invokestatic  #81    // Method sum:([II)J
107: invokedynamic #103,  0  // InvokeDynamic #0:makeConcatWithConstants:(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;
```

- **Decoder** (`crates/core/src/jvm/decode.rs`, in the core): all 202 opcodes of the JVM specification, the wide forms named as
  JDK 25's javap names them (`iload_w`, `iinc_w`), printed as `javap -c -p` prints them: constants
  with javap's comments (`// Method …`, `// InterfaceMethod …`, `// class "[I"`), a member of the
  class itself without its class, names that are not Java binary names in quotes (`"<init>"`),
  strings with Java's escapes, floating point as Java's `Double.toString` and `Float.toString`
  write it (the shortest digits, `4.9E-324`, ties to the even digit), switches with their cases,
  and `jsr` and `ret` without the operands javap leaves out. `tools/verify-jvm.mjs` compares the
  text the page shows with javap line by line: every method of the 69 modules of JDK 25 and of the
  JARs of IntelliJ IDEA and Android Studio — 276,000 classes, 52 million instructions — without a
  difference. The page asks the core for the instructions of the rows on screen.
- **Class files** (`crates/core/src/jvm/classfile.rs`, in the core): the constant pool (with its modified UTF-8), the
  class, its fields and methods, and the attributes the pages show: Code with its exception table,
  line numbers and local variables, the bootstrap methods of invokedynamic, the source file,
  signatures, inner classes, records, sealed classes, nests and modules. What the page shows of
  them — an instruction with javap's comment and the local it reads, a method's card and HLA64
  header, a class's card, a module — is written there too (`page.rs`) when it is shown, and
  `tools/diff-jvm-page.mjs` compares it with the TypeScript that read the classes before.
- **Analysis** (`crates/core/src/jvm/program.rs`, in the core): every method with code is a function, named
  `package.Class::method` and grouped by class; branches, switches and exception handlers make
  labels (`L25`), and protected ranges and handlers are marked where they start; calls are counted
  for the methods of the program — looked for in the class named, its super classes and its
  interfaces — and for the members of the classes it does not have, which are its imports; the
  bodies of lambdas and method references count as taken; the strings are those `ldc` loads; the
  entry point is the JAR's `Main-Class`. The JDK's java.base (7,300 classes, 1.7 million
  instructions) is read and analysed in about 0.6 s, twice as fast as by the TypeScript it
  replaced, and in half the memory: the classes stay in the core, which reads one again only when
  the page shows something of it.
- The **Classes** page shows the JAR's manifest, the class file versions (Java 5 … Java 25), Kotlin
  when its classes carry `kotlin.Metadata`, the module, the classes and the other files; for a
  single class its super class, interfaces and attributes. **References** shows the packages and
  classes of other libraries the code uses and the members of theirs it calls and reads.
- **HLA64** (`crates/core/src/jvm/hla.rs`): the stack folded back into statements, as for .NET —
  `sum = Hello::sum(values, len(values))`, `total += i64(values[i])`,
  `values = new int[8] { 1, 2, 3, 4, 5, 6, 7, 8 }`, `p = new Point(3, 4)` for `new`, `dup` and the
  constructor, `concat("sum=", sum)` for string concatenation and
  `` lambda<IntUnaryOperator, Hello::`lambda$main$0`>() `` for a lambda. Locals go by the names the
  class keeps (`LocalVariableTable`, `MethodParameters`) where a name means one slot, else `l3`;
  fields and methods are `obj.f` and `Class::f`, `Class::m(…)` for a static or exact call and
  `obj.m(…)` for a virtual one. The JVM's instructions say what they work on, so a comparison of
  floats is joined with its branch only where a NaN makes both mean the same — `fcmpl; ifge` is
  `if a >= b`, `dcmpg; ifge` stays `if dcmpg(a, b) >= 0`. On java.base 77% of the lines, 94% of
  the instructions, read as HLA64; on IntelliJ's own code, much of it Kotlin, 55% and 79%.

## x86-64 and i386

A Linux program or library, an Android library for x86_64 or x86, or the x86_64 slice of a macOS
program opens like the others, with the same pages; the listing is in Intel syntax, as
llvm-objdump prints it with `-M intel`.

- **Decoder** (`src/core/x86/`): every instruction LLVM 21 knows in 64- and 32-bit mode — the
  general-purpose set with APX (REX2, the new data destination, `{nf}`, `ccmp`), x87, MMX and
  3DNow!, SSE to SSE4.2, AVX and AVX2, AVX-512 with masking, broadcast and rounding, AVX10.2,
  AMX, XOP, FMA4, the crypto and system extensions — read the way LLVM's X86 disassembler reads
  them: prefixes give a context, the context and the opcode an instruction, the instruction
  where each operand is. Which instruction each encoding selects, where its operands are
  encoded and its Intel syntax come as tables, generated from LLVM's X86 target description by
  `tools/x86-index.mjs` and kept deflated (180 KB); the decoder and printer that read them are
  this project's own. `tools/verify-x86.mjs` compares them with llvm-objdump line by line: on
  31 million random encodings over every opcode map and prefix, in both modes, and on the
  Flutter engine (1.9 million instructions), WebRTC (3 million), six macOS programs (15
  million, C++, Objective-C and Rust) and the NDK's i686 and x86_64 runtimes, no line differs —
  down to what LLVM does with bytes that do not decode (it skips the bytes it read, and so does
  the listing).
- **Analysis** (`crates/core/src/x86/pass.rs`, `crates/core/src/native/x86.rs`, in the core): the code is cut into instructions as llvm-objdump
  cuts it — a sweep through each code section, starting afresh where a symbol, an export, the
  unwind table or a call says a function begins. Data is named from rip-relative operands on
  x86-64, from absolute addresses in code that is not position-independent, and on i386 PIC from
  the GOT register the code makes with `call` / `pop` (or `__x86.get_pc_thunk`) and `add`; calls
  and jumps through a GOT slot, the PLT or a Mach-O stub name the import. Switches through a
  table — of offsets from the table (x86-64 PIC), from the GOT (i386 PIC) or of addresses — get
  their cases, from the bounds check before them; a table inside the code section is shown as
  `.long` data. A stripped program's `main` is found from what `_start` passes to
  `__libc_start_main`.
- **Catalogue** (`src/data/x86-instructions.json`): 1,805 mnemonics, each with a description in
  English and Russian written for this project, its forms — the encoding as the manuals write
  it (`REX.W 01 /r`, `EVEX.512.66.0F.W0 FE /r`), the syntax with operand kinds, the extensions
  it needs — from LLVM, and a link to its page in the HTML edition of Intel's manual. `jne`
  finds `jcc`, `cmovge` `cmovcc`, `cmpltps` `cmpps`.
- **Windows** (`crates/core/src/pe.rs`, in the core): PE32 and PE32+ executables and DLLs — the import table and
  the delay-load one, with the slot of every import in the import address table, so that
  `call qword ptr [rip + …]` names its function; the exports, forwarders included; the exception
  table (`.pdata`), which lists where every function with unwind data starts, even in a stripped
  program; TLS callbacks, relocations, COFF symbols where a linker kept them, the CodeView record
  that names the PDB. What MSVC and MinGW leave is read too: the thunks of the import table
  (`jmp qword ptr [__imp_puts]`) are the imports; the table of `jmp` thunks an incremental link
  calls through is a function per thunk, named after its target (`j_name`); switches through a
  table of RVAs from `__ImageBase` get their cases; the `int3` padding between functions is one
  row (`int3 × 1 234`). A .NET assembly is recognised and refused (its code is CIL); Windows on
  Arm is described [below](#windows-on-arm). SQLite's official Windows builds (MSVC: the x64
  shell, 1.5 million instructions, and the x86 and x64 DLLs) decode exactly as llvm-objdump does.
- The HLA64 view of x86-64 is described under [HLA64](#hla64); i386 code has none.

## iOS and Objective-C

An iOS program is an arm64 Mach-O file like a Mac one, and opens the same way; an `.ipa` is a ZIP
file with the app in `Payload/Name.app`, and opening it lists what it holds to run — the app's
executable, its frameworks and extensions, each named by its `Info.plist` (`CFBundleExecutable`;
binary and XML property lists are read by `crates/core/src/plist.rs`) — so one can be taken out
and opened (`crates/core/src/bundle.rs`, in the core, which also inflates it; a zipped macOS app
works the same; `tools/diff-archive.mjs` compares the reading with the TypeScript it replaced). The **Mach-O** page then shows
the bundle, its version, the system it needs and, from `embedded.mobileprovision`, who signed it,
for which devices and until when.

- **Objective-C** (`crates/core/src/objc.rs`, in the core, handed to the page with the image): the runtime's own metadata, which a stripped program
  keeps — the class list and the category list, each class's read-only data and its metaclass,
  their method lists in both layouts (three pointers per method, or three 32-bit offsets since
  Xcode 12). Every method gets its name back as a function (`-[Greeter initWithName:]`,
  `+[Greeter defaultGreeter]`), and each stub in `__objc_stubs` is named after the selector it
  sends, as the linker named it (`objc_msgSend$initWithName:`). The code's loads are named too:
  a selector reference (`selref.init`), a class reference (`classref.NSString`), a constant
  NSString (`@"Hello, %@!"`). Swift classes are written in Swift's way (`_TtC8HelloKit7Counter`
  is `HelloKit.Counter`). Pointers are read through both kinds of dyld fixups: chained fixups
  (each rebase and bind of a chain, to its last link) and the older bind opcodes. On the
  frameworks of an iOS app (Sentry, Firebase, Protobuf, WebRTC…) and on macOS apps (CotEditor,
  Kindle, Calculator), arm64, arm64e and x86_64, the methods and their addresses are the ones
  `xcrun dyld_info -objc` lists; where it prints `(null)` for a Swift class with an `@objc` name,
  the page names it.
- **Encryption**: an app from the App Store has its code encrypted with FairPlay
  (`LC_ENCRYPTION_INFO_64`, `cryptid 1`) until the device that runs it decrypts it. Such a file
  is recognised and refused; a copy decrypted on a device (`cryptid 0`) opens.

## Windows on Arm

- **arm64** programs go through the arm64 analysis, **32-bit Arm** ones (Windows RT, IoT: Thumb-2
  only) through the AArch32 one. Imports are named whether the code calls them through a thunk
  (MinGW: `adrp x16; ldr x16, [x16, #…]; br x16`, `movw r12; movt r12; ldr.w pc, [r12]`) or, as
  MSVC does, by loading the import's slot into a register and calling through it (`ldr x8, [x8,
  #…]; blr x8`, also from a register kept across calls); on 32-bit Arm, `movw`/`movt` pairs and
  literal-pool words are absolute addresses here, not offsets from pc. The exception table of
  either gives the function starts.
- **ARM64EC and ARM64X**: Arm code that follows x64's conventions, so that x64 code in the same
  process can call it and be called by it; an ARM64X file adds plain arm64 code for Arm processes,
  and an x64 process sees another view of it, made by the dynamic relocations in its load
  configuration (they rewrite the header: machine, exports, imports). The CHPE metadata says which
  code is which (the code map), where the ARM64EC functions start and which x64 entry point stands
  for which of them. Such a file opens at its Arm code, with the x64 code left as data; the **PE**
  page shows the code map and opens the x64 code, named from the x64 view's exports. Microsoft's
  ARM64X DLLs (dbghelp, symsrv, msdia140: 1.6 million Arm instructions and their x64 code) decode
  as llvm-objdump does, which switches decoders by the same code map.
- **main**: in a stripped Windows program the C runtime's startup tells it — the call after the
  runtime hands out the environment or the command line (MSVC with the runtime in a DLL), the call
  that gets argc from what `__p___argc` returned, the image base (`WinMain`) or argc, argv and envp
  from globals (MSVC with the runtime linked in, new and old), the call just before `_cexit`
  (MinGW). The page opens there; this works the same for x86-64 and i386 programs.

## Changing instructions (macOS)

Click an instruction and **Change…** (key **E**): a window opens where the new instruction is
typed as assembly (`mov w0, #1`, `b.ne 0x…`, `nop`) or as its bytes in hex, or picked from the
few changes that fit — the opposite condition, an unconditional branch, "do nothing", "return
0/1". Whatever is typed is decoded and shown before it is applied, so what goes into the file is
exactly what the preview says and never a word that decodes to something else: the assembler
(`crates/core/src/arm64/encode.rs`) checks every instruction by decoding it back;
`tools/diff-assembler.mjs` compares it with the TypeScript assembler it replaced, word for word
and error for error, on some 16 million lines.

A change is written into the opened file at once; the listing marks the rows and the change can
be undone. **Download** saves the changed file. A macOS program's code signature holds a hash of
every page, and Apple Silicon will not run arm64 code whose pages do not match, so the file is
signed again, ad hoc — the way `codesign --sign -` and the linker sign (`crates/core/src/sign.rs`,
in the core): the page hashes are computed afresh (SHA-256, or the SHA-1 or SHA-384 the code
directory names, by the core's own `sha.rs`; `tools/diff-resign.mjs` compares the signed files
with those the TypeScript signed with the browser's crypto), the ad hoc
flag is set, the team identifier and any Developer ID signature go, the entitlements stay. In a
universal file every slice is signed again, the patched one and the rest. A file signed by a
developer loses that signature and its notarization, so macOS may ask to confirm it on first
run; if it is inside an `.app`, re-sign the bundle with `codesign --force --deep -s - Name.app`.
`tests/patch.mjs` checks the whole path on a Mac: the patched program is signed, `codesign
--verify --strict` accepts it, and it runs and returns what the new instructions say.

## How it works

- **The core in Rust** (`crates/`): what takes a whole program apart runs as WebAssembly. The
  decoders of arm64, 32-bit Arm (A32, T32, VFP, NEON) and x86 (LLVM's tables and Intel printer)
  are there, and so are the passes over every instruction: the layout of x86 and AArch32 code,
  the cross references, switch tables, labels and the HLA64 joins. Java runs there whole: a
  class file, a JAR or a .jmod is read, its classes parsed and every method analysed inside, and
  what the page shows of a class is written there when it is shown. So is a WebAssembly module: read,
  decoded and analysed inside, its functions named by the demanglers (Rust, C++, Swift, MSVC),
  which were checked against the TypeScript on 3.6 million real symbols; and so is a .NET
  assembly, its metadata read, every method decoded and named as ildasm names it, and what the
  page shows of it written there. The
  containers are read there too — Mach-O, ELF, PE — and handed to the page as JSON, with why a
  file cannot be read as a code the page words in its language. The HLA64 lines of every
  view's rows — arm64, x86-64, WebAssembly, .NET, Java — are written there as well (a module's,
  an assembly's or a JAR's session stays open for them); the names a line uses (functions as the settings name
  them, labels, strings, imports) are the page's, so the core asks for them in rounds — it
  returns the questions, the page answers, the core writes the line (`crates/wasm/src/hla.rs`) —
  and `tools/diff-hla.mjs` compares every line of real programs with the TypeScript lifter it
  replaced. The rest of `src/core` follows. `crates/core` is plain Rust with no I/O and no host — it builds natively too (`cargo
  test`, a desktop shell) — and `crates/wasm` puts a C interface on it whose module imports
  nothing, so a browser, Node, Electron or wasmtime runs the same file. Work crosses the boundary
  in bulk: the file goes in once, the pass runs inside in steps the page paces (a progress bar
  between them, no call per instruction), and the results come out once as flat arrays — a
  mnemonic number and a flag byte per instruction, cross references as sorted keys, run starts
  and instruction indices. Only small questions go one at a time: an instruction for a row on
  screen, as a short JSON text. `src/core/engine/engine.ts` is the TypeScript side; the page's
  policy allows WebAssembly (`'wasm-unsafe-eval'`) and still nothing on the network.
  `tools/diff-core.mjs` compares the analysis with the TypeScript core it replaces, on real
  programs: the same arrays, functions, references and strings, three to five times faster
  (arm64: 2 million instructions in 0.25 s rather than 0.9 s; x86-64: 4.9 million in 2 s rather
  than 9 s).
- **Decoder** (`crates/core/src/arm64/`): the A64 encoding tables by hand — data processing,
  branches and system instructions, loads and stores including the LSE atomics, scalar
  floating point, Advanced SIMD with FP16, dot product, BF16, Int8 and FP8 matrix and
  multiply-long forms, and the crypto extensions — with the aliases LLVM prints (`mov`, `cmp`,
  `lsl`, `cset`, `ubfx`, …). `tools/verify-decoder.mjs` compares it with `llvm-objdump`
  instruction by instruction: on a 2-million-instruction Rust program no line differs, on the
  Flutter engine for arm64-v8a (1.5 million) one does (data LLVM reads as SVE), and on 4 million
  random encodings only some EL2/EL3 system-register and TLB-maintenance names do.
- **Programs** (`crates/core/src/native/image.rs`, in the core): what the analysis needs of a
  file — sections, symbols, imports, exports, stubs, function starts, the Objective-C metadata —
  the same for a Mach-O, an ELF and a PE file. The core builds it, and the page takes the same
  image as JSON for its pages (`src/core/image.ts`; `tools/diff-image.mjs` compares it with the
  TypeScript that built it before on 16,800 real programs); for an analysis the core reads the
  file again, so a whole analysis needs nothing from the page but the bytes.
- **Mach-O** (`crates/core/src/macho.rs`, in the core): universal files, segments and sections, the symbol table,
  imports through the indirect symbol table, the dyld bind opcodes and chained fixups, the
  export trie, function starts, data in code, the code signature and entitlements. 32-bit files
  too: i386 programs of old macOS, whose entry point is often the thread state of
  `LC_UNIXTHREAD` (crt1's `start`), go through the x86 analysis; armv7 programs of old iOS through
  the 32-bit Arm one, where Thumb code is known from the symbols' `N_ARM_THUMB_DEF`, the low bit of
  exported and method addresses and of `LC_FUNCTION_STARTS`, and `LC_DATA_IN_CODE` marks the
  jump tables. Their Objective-C metadata, with 4-byte pointers, names the methods as in arm64.
- **Names** (`crates/core/src/demangle/`, asked by `src/core/demangle.ts`: a row's name alone, a
  page of imports in one call): Rust v0 and legacy symbols and C++ names, back to source
  names; the Rust v0 demangler matches `llvm-cxxfilt` on every symbol of the sample program.
  Swift names (`swift.rs`, `$s…` in Mach-O and ELF) are read into the tree of nodes
  Swift's own demangler builds and printed as `swift-demangle` prints them: the listing shows
  the simplified form (`Counter.increment(by:)`, `closure #1 in Model.load()`, `specialized
  …`), the details the full one (`HelloKit.Counter.increment(by: Swift.Int) -> Swift.Int`).
  `tools/verify-swift.mjs` compares both with `swift-demangle` symbol by symbol: on the 2.13
  million Swift symbols of Xcode and the apps in /Applications every one it demangles comes
  out the same; 226 rare ones (constant-propagated structs, value generics) stay as they are.
  MSVC names, those of Windows programs and DLLs (`msvc.rs`, `?f@@YAXXZ`), come out as
  LLVM's `llvm-undname` prints them in the details (`public: virtual int __cdecl
  geo::Point::length(void) const`) and as the qualified name in the list (`geo::Point::length()`,
  `std::basic_ostream<char, std::char_traits<…>>::operator<<(…)`). `tools/verify-msvc.mjs`
  compares them with llvm-undname: the same on all 1,190 names of LLVM's own tests of its
  demangler and on the 3,412 of the Visual C++ runtime DLLs (msvcp140, concrt140, vcruntime140).
- **Analysis** (`crates/core/src/arm64/pass.rs`, `crates/core/src/native/arm64.rs`, in the core): one pass over all
  instructions gives the statistics, labels, call and data references, the strings Rust code
  points at (with their length, read from the `mov` that follows), and the pairs the HLA64 view
  joins; the functions and their names (demangled in the core) come from what the file says and
  where the calls go, and so do a stripped program's `main` and the stubs of an ELF PLT or a
  Windows import table. A 2-million-instruction Rust program is analysed in under 0.2 s, about
  six times as fast as by the TypeScript this replaced.
- **Listing** (`src/app/listing.ts`): millions of rows are two typed arrays; only the rows on
  screen are drawn, and the scroll position maps to a row, since no browser can make an
  element 50 million pixels tall.
- **The page** (`build.mjs`): the code with the catalogues, 4.9 MB of JavaScript, and the core's
  WebAssembly module, 2.2 MB, go into the page as one deflated stream written seven bits to a
  character, 1.9 MB — the module as bytes, not as base64 inside the code, which deflate could not
  shrink back; a few lines of the page decode
  it, inflate it with the browser's `DecompressionStream` and run it. Each catalogue stays a
  string until the first lookup in it parses it, so opening a WebAssembly module never
  parses the x86 one.
- **The PWA** (`build/pages/`): the same run writes that page as an installable app —
  `index.html` with a manifest link and a `<meta name="service-worker">` that tells the page
  (`src/app/pwa.ts`) to register its worker, `manifest.webmanifest`, the icons and `sw.js`
  (`src/pwa/sw.js`), which keeps the page so it opens offline. Its copy of the policy lets in
  three things more, all from its own origin: the manifest, the service worker and the icons —
  `connect-src` stays `'none'`. `build/disassembler.html` itself stays one file with no
  external references.

## Build and tests

Node 22+ and nothing else at run time; to build, esbuild, TypeScript and Rust with the
WebAssembly target (`rustup target add wasm32-unknown-unknown`); Binaryen's `wasm-opt`, when it
is on the PATH, makes the core's module smaller. The module's build inlines less than opt-level 3
would (`.cargo/config.toml`) and builds the bridge (`crates/wasm`) for size: 13% smaller
deflated, the analyses at most 5% slower.

```sh
npm run check        # typecheck, unit tests, build, browser tests
npm test             # the core's module, its Rust tests, then the unit tests (decoder vectors, AArch32, x86, WebAssembly, CIL, JVM, ELF and Android, patching, Mach-O, demangler, HLA64, data, i18n)
npm run build        # build/disassembler.html and build/pages/ (the PWA)
npm run wasm         # only the core's module: target/core.wasm (tools/wasm.mjs)
node tools/wasm-opcodes.mjs                      # the core's WebAssembly instruction table from src/core/wasm/opcodes.ts (npm test checks it is current)
cargo test -p disasm-core                        # the Rust core alone, natively
node tools/diff-core.mjs <program …>             # the analysis against the TypeScript core of ../html-disasm (or ORIGINAL), with timings
node tools/diff-hla.mjs <program …>              # every HLA64 line (arm64, x86-64, WebAssembly, .NET, Java) against the TypeScript lifter
node tools/diff-assembler.mjs                    # the arm64 assembler against the TypeScript one, on millions of lines
cargo run --release -p disasm-core --example bench -- <file> <offset> <count>   # the arm64 decoder and pass, natively
npm run watch        # rebuild on every change
npm run shots -- shots/ [program]     # screenshots of every screen
node tools/pwa-icons.mjs                         # the PWA's PNG icons, from assets/icon.svg (Chrome)
node tools/verify-decoder.mjs <program>          # against llvm-objdump (needs Xcode)
node tools/verify-decoder.mjs --random 1000000   # random encodings
node tools/verify-arm32.mjs <library.so>         # AArch32 against the NDK's llvm-objdump
node tools/verify-arm32.mjs --random 1000000 --set a32|t16|t32|thumb
node tools/verify-x86.mjs <program>              # x86 against llvm-objdump -M intel (Homebrew llvm@21)
node tools/verify-x86.mjs --random 1000000 [--mode 32] [--class evex]
node tools/x86-index.mjs <llvm-project>          # the x86 tables, from LLVM's X86 target
node tools/verify-swift.mjs <program …>           # Swift names against swift-demangle (Xcode)
node tools/verify-msvc.mjs <file …>              # MSVC names against llvm-undname (Homebrew llvm@21)
node tools/verify-wasm.mjs [module.wasm …]       # against wasm-tools print
node tools/verify-wasm.mjs --random 1000         # random modules from wasm-tools smith
node tools/diff-wasm-module.mjs <module.wasm …> [--damage N]   # what the page reads of a module, against the TypeScript reader
node tools/verify-cil.mjs [assembly.dll …]       # CIL against Microsoft's ildasm
node tools/diff-cil-page.mjs <assembly.dll …> [--damage N]   # what the page shows of an assembly, against the TypeScript
node tools/diff-image.mjs <program …> [--damage N]          # the image of a native program, against the TypeScript
node tools/diff-archive.mjs <file.ipa|.apk|app.zip …> [--damage N]   # what the page reads of a ZIP file, against the TypeScript
node tools/diff-resign.mjs <program …> [--damage N]         # a patched Mach-O file signed again, against the TypeScript
node tools/verify-jvm.mjs [file.jar|.class …]    # JVM bytecode against javap (JDK 23 or newer)
node tools/diff-jvm-page.mjs <file.jar|.class …>  # what the page shows of Java classes, against the TypeScript
```

The browser test drives the built page in the installed Chrome over the DevTools protocol
(`CHROME=/path/to/chrome` to pick one; without Chrome it is skipped). `tests/pwa.mjs` serves
`build/pages/` from a local server: the service worker takes the page over, Chrome finds the
manifest installable, with the server gone the page still opens and reads a program, and a new
deploy replaces the old one by itself. `tests/fixtures/hello` is
a small program built from `hello.c` with `clang -O1 -arch arm64`;
`tests/fixtures/decode-vectors.json` has 9,700 words with the text `llvm-objdump` prints for
them, so the decoder is tested without Xcode. `tests/fixtures/hello.wasm` is the same `hello.c`
built by Emscripten 5 (`emcc -O1 -g2 -gline-tables-only -matomics -mbulk-memory -sSHARED_MEMORY`),
and `tests/fixtures/wasm-vectors.json` has 2,700 instructions with the text `wasm-tools` prints.
Checking the WebAssembly decoder needs wasm-tools (`brew install wasm-tools`).
`tests/fixtures/dotnet/` holds the same program in C# (`hello.cs`) and `more.cs`, which reaches
every kind of operand and the names and constants ildasm writes in its own ways, built by its
`build.sh` with the .NET SDK into `hello.dll`, and `hello.il`, ildasm's text of it, which
`tests/cil.mjs` compares the rows the page shows with. Checking the CIL decoder needs ildasm, which Microsoft
publishes on NuGet (`runtime.osx-arm64.Microsoft.NETCore.ILDAsm`, unzipped into `private/ildasm`,
or `ILDASM=/path/to/ildasm`).
`tests/fixtures/jvm/` holds the same program in Java (`src/hello/Hello.java`, compiled with its
locals' names) and `More.java`, which reaches every kind of operand and the constants javap writes
in its own ways, and `Odd.java`, which writes with the ClassFile API what javac cannot: a Java 5
class with subroutines (`jsr`, `ret`, their wide forms), method handle, method type and dynamic
constants, every stack operation and names javap quotes; its `build.sh` (JDK 25) makes them into
`hello.jar`, and `hello.javap`, javap's text of it, which `tests/jvm.mjs` compares the rows the
page shows with.
`tests/fixtures/android/` holds the same program for Android, built by its `build.sh` with the
NDK: `hello.c` as Thumb-2 and `arm.c` as A32 for armeabi-v7a, both for arm64-v8a, stripped as
in an APK, the armeabi-v7a one also with its symbol table (the tests check the stripped analysis
against its mapping symbols), and `hello.apk` holding both. `tests/fixtures/arm32-vectors.json`
has 5,500 AArch32 instructions with the text llvm-objdump prints. Checking the AArch32 decoder
needs the Android NDK (`ANDROID_NDK`, or the newest one in `~/Library/Android/sdk/ndk`).
`tests/fixtures/x86-vectors.json` has 14,000 x86-64 and i386 instructions with the text
`llvm-objdump -M intel` prints; checking the x86 decoder needs LLVM 21 (`brew install llvm@21`),
whose X86 target the tables are made from. `tests/fixtures/x86/` holds `hello.c` built by its
`build.sh` for Linux (x86-64 and i386, with zig), for Windows (x64 and x86 programs and an x64
DLL, with zig and MinGW), for Android (x86_64 and x86, stripped) and for macOS (a universal file
with x86_64 and arm64), and `msvc.cpp` as a C++ DLL with MSVC's names (`hello-msvc.dll`, clang
and lld-link). `tests/fixtures/msvc-vectors.json` has the 1,190 names of LLVM's tests of its
MSVC demangler with the text llvm-undname prints. `tests/fixtures/ios/` holds a small iOS app built by its `build.sh` with
Xcode: an Objective-C executable (`hello.m`: a class, a category, NSString constants) and a Swift
framework, stripped, and `Hello.ipa` holding both with their binary `Info.plist` files; the same
executable linked with the older bind opcodes is `HelloClassic`. `tests/fixtures/winarm/` holds
`hello.c` built by its `build.sh` for Windows on arm64 and on 32-bit Arm (zig), two DLLs that call
imports the way MSVC does, and an ARM64EC and an ARM64X DLL linked by lld-link 21 (Homebrew's
`lld@21`). `tests/fixtures/linux/` holds the x86 `hello.c` built by its `build.sh` (zig) as Linux
programs for arm64 and armhf, the armhf one in A32 and in Thumb-2, stripped, and with their
symbol tables for the mapping symbols. `tests/fixtures/macho32/` holds 32-bit Mach-O programs
built by its `build.sh`: `hello.c` for armv7 (stripped, and with its symbols), the iOS `hello.m`
for armv7, a universal file with armv7 and arm64, and `hello.c` for i386 starting through
`LC_UNIXTHREAD`. Xcode still links armv7 against the stand-in libraries there; i386 is linked by
ld64 built from cctools-port. `tests/fixtures/swift-vectors.json` has 356 Swift symbols
of the standard library and the SDK frameworks with the text `swift-demangle` prints for them,
in full and simplified.

## Versions and releases

The version is written in one place, `package.json`. The build puts it into the page (the line
at the bottom of the start page) and into the PWA's cache name. A build of the commit tagged
`v<version>` shows it as it is; any other adds its commit, `0.1.0+1a2b3c4`, so a page from
`main` on GitHub Pages is not taken for the release.

```sh
npm version minor           # 0.1.0 -> 0.2.0: package.json, package-lock.json, a commit and the tag v0.2.0
git push --follow-tags      # the tag starts .github/workflows/release.yml
```

The release workflow stops if the tag and `package.json` disagree, runs the typecheck and the
unit tests, then attaches `disassembler-<tag>.html` and `SHA256SUMS.txt` to the release.
`.github/workflows/test.yml` runs the same on every push and pull request. The browser tests
stay local: they depend on the runner's Chrome and its timing, so `npm run check` runs them
before a commit.

## GitHub Pages

`.github/workflows/pages.yml` builds and unit-tests every push to `main` and deploys `build/pages/`
to GitHub Pages (Settings → Pages → Source: GitHub Actions; Custom domain:
`disasm.marketkernel.com`), at <https://disasm.marketkernel.com>. Programs open there as in the single file, from
the disk, and are not uploaded.

Each deploy changes the cache name in `sw.js`, so the browser picks up the new worker by itself
on a launch with a connection. The new worker downloads its version and takes over at once:
the page keeps nothing a new version could lose, so the window already open goes on with the
code it runs, and the next launch or reload is the new version, offline too. That is also the
trade-off: an installed PWA runs whatever the last deploy put there, while a downloaded file
stays the version it is. For a version fixed on disk, take `disassembler-<tag>.html` from a
release and compare it with `SHA256SUMS.txt`.

## Translations

The interface speaks English and Russian: **Settings → Language** (as the system, English,
Русский). Switching redraws everything at once; the program is not read again.

- Interface strings are `t('context', 'English text')` and `tn(…)` with plain literals in the
  code and `data-i18n` in the template; the Russian dictionary is `src/locales/ru.json`.
  `node tools/i18n.mjs` lists what a dictionary lacks or no longer needs.
- The instruction texts are translated too: `src/data/arm64-instructions.ru.json` holds the
  Russian name and description of every instruction and the names of the conditions,
  `src/data/hla64-words.ru.json` the descriptions of the HLA64 words. The English files stay the
  source of the structure (forms, syntax, formulas, links); the translations hold only text, and
  whatever they lack shows in English.
- `tests/i18n.mjs` checks that the dictionary has every string and no stale ones, the same
  placeholders, and all four Russian plural forms; `tests/data.mjs` that every instruction,
  condition and word has its Russian text.

Another language is a dictionary in `src/locales`, its name in `src/core/i18n.ts`, and the two
`*.<code>.json` files in `src/data` registered in `src/core/catalog.ts`.

## Layout

| Path | What |
| --- | --- |
| `crates/core/` | the core in Rust, no I/O, no host: `src/arm64/` (the decoder, `decode.rs` and `simd.rs`; instructions and operands, `types.rs`; system registers; HLA64, `hla.rs`; the assembler, `encode.rs`; the pass over a program, `pass.rs`), `src/arm32/` (A32, T32, VFP/NEON decoders; the layout and pass, `pass.rs`), `src/x86/` (the decoder and Intel printer with LLVM's tables, `tables.bin` from `tools/x86-rust.mjs`; HLA64; the layout and pass), the image's sections and strings (`image.rs`), what the HLA64 lifters share (`lift.rs`), cross references as flat arrays (`refs.rs`), inline strings and JavaScript's number formatting (`text.rs`); `src/jvm/` (class files, the decoder, the analysis of a class file, a JAR or a .jmod, `program.rs`, HLA64, `hla.rs`, and what the page shows of a class, `page.rs`) with `zip.rs` for the archives, `plist.rs` (property lists) and `bundle.rs` (the programs of an app archive), `sign.rs` and `sha.rs` (signing a patched Mach-O file again); `src/wasm/` (the module reader, the decoder with the instruction table `opcodes_table.rs` that `tools/wasm-opcodes.mjs` writes from `src/core/wasm/opcodes.ts`, the DWARF lines, the analysis of a module, `program.rs`, and HLA64, `hla.rs`), `src/demangle/` (Rust, C++, Swift and MSVC names, for the analysis and the page), `src/cil/` (.NET metadata, names and signatures as ildasm writes them, the decoder, the analysis of an assembly, `program.rs`, HLA64, `hla.rs`, and what the page shows of it, `page.rs`), `macho.rs`, `elf.rs` and `pe.rs` (the containers) |
| `crates/wasm/` | the core as a WebAssembly module with a C interface and no imports |
| `src/core/engine/engine.ts` | the module as the TypeScript sees it: loading, sessions, copying results out, the core's errors |
| `src/core/arm64/decode.ts` | the decoder's TypeScript face (one instruction per call) |
| `src/core/arm64/types.ts` | decoded instructions and their operands; formatting |
| `src/core/arm32/` | AArch32: A32 (`a32.ts`), T32 (`thumb.ts`), VFP/NEON/crypto (`simd*.ts`), the analysis (`program.ts`) |
| `src/core/x86/` | x86-64 and i386: the decoder (`decode.ts`), the Intel printer (`print.ts`), the tables generated from LLVM (`tables.ts`), the analysis (`program.ts`) |
| `src/core/arm64/encode.ts` | the assembler, for changing an instruction: the core's, with its errors in the page's language |
| `src/core/patch.ts` | changing bytes, and the core signing a macOS file again |
| `src/core/macho.ts` | a Mach-O file as the pages use it, from the core's reading; pointers and strings at addresses |
| `src/core/elf.ts` | an ELF file as the pages use it, from the core's reading |
| `src/core/pe.ts` | a PE file (Windows) as the pages use it, from the core's reading |
| `src/core/objc.ts` | the shape of the Objective-C classes, methods and references the core reads |
| `src/core/archive.ts` | ZIP files read by the core: an app's programs and its provisioning profile, an APK's native libraries |
| `src/core/image.ts` | Mach-O, ELF and PE as the pages see them, from the core's image, and the file the core reads again |
| `src/core/demangle.ts` | names back to source, from the core: Rust, C++, Swift, MSVC |
| `src/core/program.ts` | an arm64 program over the core's analysis: its pass, functions, names and strings |
| `src/core/hla.ts` | instructions as HLA64: the lines come from the core, the names they use from the page |
| `src/core/disassembly.ts` | what both architectures share: instructions, functions, references, strings |
| `src/core/wasm/` | WebAssembly: the module and its instructions as the core reads them, DWARF line lookup, opcodes for the catalogue, the program over the core's analysis, the marks of HLA64 lines |
| `src/core/cil/` | .NET: opcodes for the catalogue, the program over the core's analysis, and what the page shows of an instruction, a method or the assembly, as the core writes it |
| `src/core/jvm/` | Java: opcodes for the catalogue, the program over the core's analysis, and what the page shows of an instruction, a method or a class, as the core writes it |
| `src/core/rows.ts` | the rows of the listing |
| `src/core/bytes.ts` | UTF-8 and LEB128, as the file formats share them |
| `src/core/catalog.ts` | lookups in the catalogues and the HLA64 words, in the interface language |
| `src/core/i18n.ts` | interface languages |
| `src/data/arm64-instructions.json` | the instruction catalogue |
| `src/data/arm32-instructions.json` | the AArch32 catalogue |
| `src/data/x86-instructions.json` | the x86 catalogue |
| `src/data/wasm-instructions.json` | the WebAssembly catalogue |
| `src/data/cil-instructions.json` | the CIL catalogue |
| `src/data/jvm-instructions.json` | the JVM catalogue |
| `src/data/hla64-words.json` | the HLA64 vocabulary, with the new words |
| `src/data/*.ru.json`, `src/locales/ru.json` | Russian: instruction texts, HLA64 words, the interface |
| `src/app/labels.ts` | names of categories, flags, section and file types in the interface language |
| `src/app/pwa.ts` | the PWA's service worker, registered only in `build/pages/` |
| `src/pwa/sw.js` | the service worker of the Pages build |
| `assets/` | the icon; `pwa/`, its PNG sizes for the PWA (`tools/pwa-icons.mjs`) |
| `.github/workflows/` | tests on every push, the Pages deploy, releases |
| `src/app/` | the page: template, styles, listing, details panel (`cards.ts`, the cards every architecture's panel is built of), pages, reference, search; `views.ts`, what differs between kinds of program, looked up by the open one's architecture; `wasm.ts`, `cil.ts`, `jvm.ts`, `arm32.ts`, `x86.ts`, `elf.ts`, `pe.ts` and `patch.ts` its WebAssembly, .NET, Java, 32-bit Arm, x86, ELF, PE and editing parts |
| `tools/` | Arm XML indexers (A64, AArch32), the x86 table generator, decoder verification (arm64, AArch32, x86, WebAssembly, CIL, JVM), ELF wrappers for llvm-objdump, Chrome driver, screenshots, the PWA icons, i18n |
| `tests/` | unit tests and the browser tests (the single file, the PWA) |

## Limitations

- arm64 (and arm64e), x86_64, i386 and armv7 Mach-O, x86-64, i386, arm64 (ARM64EC and ARM64X included) and
  32-bit Arm PE (Windows), arm64, 32-bit Arm, x86-64 and i386 ELF (Android, Linux), WebAssembly
  core modules, .NET assemblies (their IL), Java class files and JARs; WebAssembly components are
  recognised and refused, and so are an APK's Dalvik bytecode (`classes.dex`) and big-endian ELF. FP16 and stack-switching WebAssembly proposals are not
  decoded (the rest of such a function shows as `.bytes`).
- SVE and SME are shown as `.inst` words.
- The native code of mixed-mode (C++/CLI) and ReadyToRun .NET assemblies is not shown, only their
  IL, and the listing marks where each try block and handler starts rather than drawing ildasm's
  `.try { … }` blocks.
- A JAR's classes for other Java releases (`META-INF/versions/…`) are counted, not shown, and the
  JARs inside a JAR (a Spring Boot `BOOT-INF/lib`) are listed, not opened.
- In a stripped armeabi-v7a library, data nothing refers to (a table of addresses in `.text`)
  is shown as instructions, as llvm-objdump shows it without mapping symbols.
- Functions come from the symbol table, the export trie, `LC_FUNCTION_STARTS` and call targets;
  there is no control-flow recovery beyond branch arrows and labels, and no decompilation.
- The legacy Objective-C runtime of i386 macOS programs (the `__OBJC` segment) is not read.
- Of Swift's metadata only the names of classes the Objective-C runtime sees are read; Swift's
  own type descriptors and field records are not.
- Of DWARF only the line tables are read; Go's strings, which have no NUL, are found only where
  the code points at them.

## License

MIT. The Arm A64 and AArch32 ISA XML are not part of this repository; only facts taken from
them (instruction names, forms, syntax templates) are. The WebAssembly descriptions are written for this project and
link to the specification, and so are the CIL descriptions, which link to Microsoft Learn's
`OpCodes` pages (ECMA-335 is the authoritative text). The x86 decoding tables (`src/core/x86/tables.ts`) are generated from
the X86 target description of [LLVM](https://llvm.org), which is under the Apache License 2.0
with LLVM Exceptions: which instruction each encoding selects, where its operands are, and its
Intel syntax; the decoder that reads them is this project's own.
