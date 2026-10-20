/**
 * Objective-C metadata of a Mach-O image, as the runtime reads it: the
 * classes and categories with their methods, the selector and class
 * references the code loads, and the constant NSStrings. iOS and macOS
 * programs keep these even when they are stripped, so every method gets its
 * name back (`-[Greeter greeting]`), and a call through objc_msgSend shows
 * what it sends (`@selector(initWithName:)`).
 *
 * The lists are pointers that dyld fixes up when it loads the image: a
 * pointer into the image itself is a rebase, read from its chained-fixup
 * encoding; one to a class of another library is a bind, named by its
 * import (`_OBJC_CLASS_$_NSObject`). Method lists come in two layouts: three
 * pointers per method, or (Xcode 12 and later) three 32-bit offsets from the
 * entry itself. A 32-bit (armv7) image has the same structures with 4-byte
 * pointers; old i386 macOS programs use the legacy runtime, which is not read.
 *
 * The core reads them (crates/core/src/objc.rs) with the image (image.ts); what is here is their shape.
 */

export interface ObjcMethod {
  /** `-[Greeter greeting]`, `+[Greeter defaultGreeter]` */
  name: string;
  selector: string;
  /** Where its code is (0 when the method has none here). */
  imp: number;
  classMethod: boolean;
}

export interface ObjcClass {
  /** As the runtime names it; a Swift class also has its source name in `swift`. */
  name: string;
  swift?: string;
  /** Where its class_t (or category_t) is. */
  addr: number;
  superclass?: string;
  /** For a category: its name; the class it extends is `name`. */
  category?: string;
  methods: ObjcMethod[];
}

export interface Objc {
  classes: ObjcClass[];
  categories: ObjcClass[];
  protocols: string[];
  /** A selector reference → the selector: what `ldr x1, [selref]` loads. */
  selrefs: Map<number, string>;
  /** A class reference → the class name. */
  classrefs: Map<number, string>;
  /** A constant NSString (`__cfstring`) → its text. */
  cfstrings: Map<number, string>;
  /** Method code → `-[Class selector]`. */
  methods: Map<number, string>;
  /** An arm64 `__objc_stubs` entry → the selector it sends (the linker names it `objc_msgSend$selector`). */
  stubs: Map<number, string>;
}
