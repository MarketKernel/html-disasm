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
 */

import { bytesAt, cstringAt, pointerAt, type MachO, type Section } from './macho';

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

const CLASS_PREFIX = /^_OBJC_(?:META)?CLASS_\$_/;

/**
 * A Swift class's runtime name as Swift writes it: `_TtC5Hello14ViewController`
 * is Hello.ViewController (nested classes repeat the C).
 */
export function swiftClassName(name: string): string | undefined {
  const m = /^_Tt([CP]+)(.*)$/.exec(name);
  if (!m) return undefined;
  let rest = m[2]!;
  const parts: string[] = [];
  if (rest.startsWith('s')) {
    parts.push('Swift');
    rest = rest.slice(1);
  }
  while (rest) {
    const n = /^(\d+)/.exec(rest);
    if (!n) return undefined;
    const len = Number(n[1]);
    parts.push(rest.slice(n[1]!.length, n[1]!.length + len));
    rest = rest.slice(n[1]!.length + len);
  }
  return parts.length >= 2 ? parts.join('.') : undefined;
}

export function parseObjc(m: MachO): Objc | undefined {
  const find = (name: string): Section[] => m.sections.filter((s) => s.sectname === name && s.offset);
  const classlist = find('__objc_classlist');
  const catlist = find('__objc_catlist');
  const selrefSections = find('__objc_selrefs');
  if (!classlist.length && !catlist.length && !selrefSections.length) return undefined;
  if (![0x0100000c, 0x01000007, 12, 7].includes(m.cputype)) return undefined;
  // Pointer-sized fields: 8 bytes, or 4 in a 32-bit image, where class_ro_t has no padding before its name.
  const P = m.is64 ? 8 : 4;
  const roName = m.is64 ? 24 : 16;
  const roMethods = roName + P;
  const out: Objc = { classes: [], categories: [], protocols: [], selrefs: new Map(), classrefs: new Map(), cfstrings: new Map(), methods: new Map(), stubs: new Map() };

  const u32 = (addr: number): number | undefined => {
    const b = bytesAt(m, addr, 4);
    return b && b.length === 4 ? new DataView(b.buffer, b.byteOffset, 4).getUint32(0, true) : undefined;
  };
  const i32 = (addr: number): number | undefined => {
    const v = u32(addr);
    return v === undefined ? undefined : v | 0;
  };
  /** A pointer field: the name it is bound to, or the address it holds. */
  const bound = (addr: number): string | undefined => m.stubs.get(addr);
  const ptr = (addr: number): number | undefined => {
    if (bound(addr)) return undefined;
    const v = pointerAt(m, addr);
    // Pointer authentication and Swift's flag bits live outside the address.
    return v === undefined || v === 0 ? undefined : v % 2 ** 47;
  };
  const string = (addr: number | undefined): string | undefined => (addr === undefined ? undefined : cstringAt(m, addr, 1024));
  const classNameAt = (field: number): string | undefined => {
    const name = bound(field);
    if (name) return name.replace(CLASS_PREFIX, '');
    const cls = ptr(field);
    return cls === undefined ? undefined : className(cls);
  };
  const roOf = (cls: number): number | undefined => {
    const data = ptr(cls + 4 * P);
    // FAST_DATA_MASK: the low bits are flags (Swift classes set 1 or 2).
    return data === undefined ? undefined : data - (data % (P === 8 ? 8 : 4));
  };
  const className = (cls: number): string | undefined => {
    const ro = roOf(cls);
    return ro === undefined ? undefined : string(ptr(ro + roName));
  };

  const methodsAt = (list: number | undefined, owner: string, classMethod: boolean): ObjcMethod[] => {
    if (list === undefined) return [];
    const flags = u32(list);
    const count = u32(list + 4);
    if (flags === undefined || count === undefined || count > 1 << 16) return [];
    const small = !!(flags & 0x80000000);
    const size = flags & 0xfffc;
    const methods: ObjcMethod[] = [];
    for (let i = 0; i < count; i++) {
      const at = list + 8 + i * size;
      let selector: string | undefined;
      let imp = 0;
      if (small) {
        // Offsets from each field: the name to a selector reference, the code to itself.
        const nameOffset = i32(at);
        const impOffset = i32(at + 8);
        if (nameOffset === undefined || impOffset === undefined) break;
        // In the shared cache the offset is to the selector itself; in an image, to its reference.
        selector = flags & 0x40000000 ? string(at + nameOffset) : string(ptr(at + nameOffset));
        imp = impOffset ? at + 8 + impOffset : 0;
      } else {
        selector = string(ptr(at));
        imp = ptr(at + 2 * P) ?? 0;
      }
      if (!selector) continue;
      const name = `${classMethod ? '+' : '-'}[${owner} ${selector}]`;
      methods.push({ name, selector, imp, classMethod });
      if (imp && !out.methods.has(imp)) out.methods.set(imp, name);
    }
    return methods;
  };

  for (const section of classlist) {
    for (let at = section.addr; at + P <= section.addr + section.size; at += P) {
      const cls = ptr(at);
      if (cls === undefined) continue;
      const ro = roOf(cls);
      const name = ro === undefined ? undefined : string(ptr(ro + roName));
      if (!name || ro === undefined) continue;
      const swift = swiftClassName(name);
      const shown = swift ?? name;
      const methods = methodsAt(ptr(ro + roMethods), shown, false);
      // The metaclass (the class's isa) has the class methods.
      const meta = ptr(cls);
      const metaRo = meta === undefined ? undefined : roOf(meta);
      if (metaRo !== undefined) methods.push(...methodsAt(ptr(metaRo + roMethods), shown, true));
      out.classes.push({ name, ...(swift ? { swift } : {}), addr: cls, superclass: classNameAt(cls + P), methods });
    }
  }
  for (const section of catlist) {
    for (let at = section.addr; at + P <= section.addr + section.size; at += P) {
      const cat = ptr(at);
      if (cat === undefined) continue;
      const category = string(ptr(cat));
      const owner = classNameAt(cat + P) ?? '?';
      const shown = swiftClassName(owner) ?? owner;
      const methods = [...methodsAt(ptr(cat + 2 * P), shown, false), ...methodsAt(ptr(cat + 3 * P), shown, true)];
      out.categories.push({ name: owner, addr: cat, category: category ?? '', methods });
    }
  }
  for (const section of find('__objc_protolist')) {
    for (let at = section.addr; at + P <= section.addr + section.size; at += P) {
      const proto = ptr(at);
      const name = proto === undefined ? undefined : string(ptr(proto + P));
      if (name) out.protocols.push(swiftClassName(name) ?? name);
    }
  }
  for (const section of selrefSections) {
    for (let at = section.addr; at + P <= section.addr + section.size; at += P) {
      const name = string(ptr(at));
      if (name) out.selrefs.set(at, name);
    }
  }
  for (const section of [...find('__objc_classrefs'), ...find('__objc_superrefs')]) {
    for (let at = section.addr; at + P <= section.addr + section.size; at += P) {
      const name = classNameAt(at);
      if (name) out.classrefs.set(at, swiftClassName(name) ?? name);
    }
  }
  // CFString: isa, flags, the characters, the length. Flag 0x7d0 has UTF-16 characters, 0x7c8 bytes.
  for (const section of find('__cfstring')) {
    for (let at = section.addr; at + 4 * P <= section.addr + section.size; at += 4 * P) {
      const flags = u32(at + P);
      const chars = ptr(at + 2 * P);
      const length = u32(at + 3 * P);
      if (chars === undefined || length === undefined || length > 1 << 20) continue;
      if (flags === 0x7d0) {
        const b = bytesAt(m, chars, length * 2);
        if (b && b.length === length * 2) {
          let text = '';
          for (let i = 0; i < length; i++) text += String.fromCharCode(b[i * 2]! | (b[i * 2 + 1]! << 8));
          out.cfstrings.set(at, text);
        }
      } else {
        const text = cstringAt(m, chars, Math.max(length + 1, 1));
        if (text !== undefined) out.cfstrings.set(at, text);
      }
    }
  }
  // An objc_msgSend stub loads its selector with adrp + ldr x1, then jumps to objc_msgSend:
  // through the GOT in 32 bytes, or with a direct b in 12 (-objc_stubs_small).
  if (m.cputype === 0x0100000c) {
    for (const section of find('__objc_stubs')) {
      for (let at = section.addr; at + 12 <= section.addr + section.size; ) {
        const adrp = u32(at);
        const ldr = u32(at + 4);
        if (adrp === undefined || ldr === undefined || (adrp & 0x9f00001f) >>> 0 !== 0x90000001 || (ldr & 0xffc003ff) >>> 0 !== 0xf9400021) {
          at += 4;
          continue;
        }
        const page = (at - (at % 4096)) + (((((adrp >>> 29) & 3) | (((adrp >>> 5) & 0x7ffff) << 2)) << 11) >> 11) * 4096;
        const selector = out.selrefs.get(page + ((ldr >>> 10) & 0xfff) * 8);
        if (selector) out.stubs.set(at, selector);
        at += ((u32(at + 8) ?? 0) & 0xfc000000) === 0x14000000 ? 12 : 32;
      }
    }
  }
  return out;
}
