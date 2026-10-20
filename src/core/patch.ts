/**
 * Changing instructions in a macOS program and signing it again.
 *
 * A patch is new bytes at an address of the opened slice; the file keeps its
 * size and layout, so nothing else moves. What does change is the code
 * signature: it holds a hash of every page of the file up to the signature,
 * and Apple Silicon does not run arm64 code whose pages do not match. So the
 * patched file is signed again, ad hoc — the way `codesign --sign -` and the
 * linker sign — in its existing room:
 *
 * - the code directory is kept, with the page hashes computed afresh, the ad
 *   hoc flag set and the team identifier dropped (an ad hoc signature has no
 *   team);
 * - the entitlements (XML and DER) stay, byte for byte, so their hashes in
 *   the code directory still hold;
 * - the requirements become the empty set, as ad hoc signing writes them;
 * - the CMS blob of a Developer ID signature and the alternate code
 *   directories go: there is no certificate to sign with here.
 *
 * In a universal file every slice is signed again, the untouched ones too:
 * codesign refuses a file whose slices mix ad hoc and Developer ID signatures.
 *
 * The hashes of the bundle's Info.plist and resources stay as they were: the
 * patch does not touch those files. The core signs (crates/core/src/sign.rs),
 * with its own SHA-1, SHA-256 and SHA-384.
 */

import { engine } from './engine/engine';
import { parseMachO, type MachO } from './macho';

export interface Patch {
  /** The address of the first byte changed. */
  addr: number;
  /** Where that byte is in the whole file (a universal file included). */
  offset: number;
  before: Uint8Array;
  after: Uint8Array;
}

/** The offset in the whole file of an address of the opened slice, or undefined if no file bytes are behind it. */
export function fileOffsetOf(image: MachO, addr: number, length: number): number | undefined {
  for (const s of image.sections) {
    if (addr < s.addr || addr + length > s.addr + s.size) continue;
    const type = s.flags & 0xff;
    if (!s.offset || type === 1 || type === 0xc || type === 0x12) return undefined;
    return image.sliceOffset + s.offset + (addr - s.addr);
  }
  return undefined;
}

/** Writes a patch's new bytes into the file (or, to undo it, its old ones). */
export function applyPatch(file: Uint8Array, patch: Patch, undo = false): void {
  file.set(undo ? patch.before : patch.after, patch.offset);
}

/** What the signature was before signing again, for the page to say what was lost. */
export interface Resigned {
  /** The signature the slice had: none, ad hoc (also the linker's), or by a developer certificate. */
  was: 'none' | 'adhoc' | 'developer';
  team?: string;
  identifier?: string;
  /** Entitlements kept in the new signature. */
  entitlements: boolean;
}

export class CannotSign extends Error {}

/**
 * Signs every slice of a file again, ad hoc — the opened one with its
 * patches, the others as they are — and says what the opened one had. The
 * core signs (crates/core/src/sign.rs): the file goes in, comes back signed.
 */
export async function resignFile(file: Uint8Array, image: MachO): Promise<Resigned> {
  const e = engine();
  const ptr = e.put(file);
  let r: { was: Resigned['was']; team: string | null; identifier: string; entitlements: boolean } | { cannot: string } | { range: true } | { parse: number };
  try {
    r = JSON.parse(e.out(e.call(() => e.x.macho_resign(ptr, file.length))));
    file.set(new Uint8Array(e.x.memory.buffer, ptr, file.length));
  } finally {
    e.free(ptr, file.length);
  }
  if ('cannot' in r) throw new CannotSign(r.cannot);
  // Where the TypeScript's typed arrays threw: a hash or the signature past its room.
  if ('range' in r) throw new RangeError('offset is out of bounds');
  if ('parse' in r) {
    // A slice that is not Mach-O: reading it says why, in the page's words.
    const arch = image.arches[r.parse];
    parseMachO(arch ? file.subarray(arch.offset, arch.offset + arch.size) : file);
    throw new CannotSign('a slice cannot be read');
  }
  return { was: r.was, ...(r.team !== null ? { team: r.team } : {}), identifier: r.identifier, entitlements: r.entitlements };
}
