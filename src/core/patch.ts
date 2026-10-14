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
 * patch does not touch those files. SHA-256 comes from the browser's own
 * crypto (crypto.subtle), which works offline.
 */

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

const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
const CSMAGIC_REQUIREMENTS = 0xfade0c01;
const CSSLOT_CODEDIRECTORY = 0;
const CSSLOT_REQUIREMENTS = 2;
const CSSLOT_ENTITLEMENTS = 5;
const CSSLOT_DER_ENTITLEMENTS = 7;
const CSSLOT_ALTERNATE = 0x1000;
const CSSLOT_SIGNATURE = 0x10000;
const CS_ADHOC = 0x2;
const CS_LINKER_SIGNED = 0x20000;

/** Hash types of a code directory, as Web Crypto names them; SHA-256 truncated to 20 bytes is type 3. */
const HASHES: Record<number, { name: string; length: number }> = {
  1: { name: 'SHA-1', length: 20 },
  2: { name: 'SHA-256', length: 32 },
  3: { name: 'SHA-256', length: 20 },
  4: { name: 'SHA-384', length: 48 },
};

const be32 = (b: Uint8Array, at: number) => ((b[at]! << 24) | (b[at + 1]! << 16) | (b[at + 2]! << 8) | b[at + 3]!) >>> 0;
const put32 = (b: Uint8Array, at: number, v: number) => {
  b[at] = v >>> 24;
  b[at + 1] = (v >>> 16) & 0xff;
  b[at + 2] = (v >>> 8) & 0xff;
  b[at + 3] = v & 0xff;
};

async function digest(name: string, length: number, data: Uint8Array): Promise<Uint8Array> {
  const hash = new Uint8Array(await crypto.subtle.digest(name, data as Uint8Array<ArrayBuffer>));
  return hash.subarray(0, length);
}

/**
 * Signs the opened slice of `file` again, ad hoc, in place. The slice must
 * already hold the patched bytes. Throws CannotSign when the slice has no
 * signature to rewrite or the new one would not fit its room.
 */
export async function resign(file: Uint8Array, image: MachO): Promise<Resigned> {
  const at = image.signatureAt;
  if (!at) throw new CannotSign('no LC_CODE_SIGNATURE');
  const slice = file.subarray(image.sliceOffset, image.sliceOffset + image.bytes.length);
  const sig = slice.subarray(at.offset, at.offset + at.size);
  if (sig.length < 12 || be32(sig, 0) !== CSMAGIC_EMBEDDED_SIGNATURE) throw new CannotSign('no embedded signature');

  // The blobs of the old signature.
  const count = be32(sig, 8);
  const blobs: { type: number; data: Uint8Array }[] = [];
  for (let i = 0; i < count; i++) {
    const type = be32(sig, 12 + i * 8);
    const offset = be32(sig, 16 + i * 8);
    if (offset + 8 > sig.length) continue;
    const length = be32(sig, offset + 4);
    blobs.push({ type, data: sig.slice(offset, offset + length) });
  }
  // The code directory to keep: the one with the strongest hash the kernel checks.
  const directories = blobs.filter((b) => (b.type === CSSLOT_CODEDIRECTORY || (b.type >= CSSLOT_ALTERNATE && b.type < CSSLOT_ALTERNATE + 5)) && be32(b.data, 0) === CSMAGIC_CODEDIRECTORY);
  const rank = (b: { data: Uint8Array }) => [0, 1, 3, 2, 4][b.data[37]!] ?? 0;
  const chosen = directories.sort((a, b) => rank(b) - rank(a))[0];
  if (!chosen) throw new CannotSign('no code directory');
  const cd = chosen.data;
  const hash = HASHES[cd[37]!];
  if (!hash) throw new CannotSign(`hash type ${cd[37]}`);

  const version = be32(cd, 8);
  const flags = be32(cd, 12);
  const hashOffset = be32(cd, 16);
  const identifier = (() => {
    const start = be32(cd, 20);
    let end = start;
    while (end < cd.length && cd[end]) end++;
    return new TextDecoder().decode(cd.subarray(start, end));
  })();
  const nSpecial = be32(cd, 24);
  const nCode = be32(cd, 28);
  const codeLimit = be32(cd, 32);
  const hashSize = cd[36]!;
  const pageSize = cd[39]! ? 2 ** cd[39]! : codeLimit;
  const teamAt = version >= 0x20200 ? be32(cd, 48) : 0;
  const team = teamAt ? new TextDecoder().decode(cd.subarray(teamAt, cd.indexOf(0, teamAt))) : undefined;
  const developer = blobs.some((b) => b.type === CSSLOT_SIGNATURE && b.data.length > 8);
  const was: Resigned['was'] = developer ? 'developer' : 'adhoc';

  // The code directory afresh: ad hoc, no team, every page hashed again.
  const next = cd.slice();
  put32(next, 12, ((flags & ~CS_LINKER_SIGNED) | CS_ADHOC) >>> 0);
  if (teamAt) put32(next, 48, 0);
  const pages = Math.ceil(codeLimit / pageSize);
  if (pages !== nCode) throw new CannotSign('the page count does not match the code limit');
  const hashes = await Promise.all(Array.from({ length: pages }, (_, i) => digest(hash.name, hashSize, slice.subarray(i * pageSize, Math.min(codeLimit, (i + 1) * pageSize)))));
  hashes.forEach((h, i) => next.set(h, hashOffset + i * hashSize));

  // The requirements an ad hoc signature carries: none. Their special slot (if the directory has
  // one) gets the new blob's hash; the entitlements' slots stay right, the blobs being the same.
  const requirements = new Uint8Array(12);
  put32(requirements, 0, CSMAGIC_REQUIREMENTS);
  put32(requirements, 4, 12);
  const keep = blobs.filter((b) => b.type !== CSSLOT_CODEDIRECTORY && b.type !== CSSLOT_SIGNATURE && !(b.type >= CSSLOT_ALTERNATE && b.type < CSSLOT_ALTERNATE + 5));
  const hadRequirements = keep.some((b) => b.type === CSSLOT_REQUIREMENTS);
  const others = keep.map((b) => (b.type === CSSLOT_REQUIREMENTS ? { type: b.type, data: requirements } : b));
  if (hadRequirements && nSpecial >= CSSLOT_REQUIREMENTS) next.set(await digest(hash.name, hashSize, requirements), hashOffset - CSSLOT_REQUIREMENTS * hashSize);

  // The new superblob, in the old one's room; what is left is zeros.
  const parts = [{ type: CSSLOT_CODEDIRECTORY, data: next }, ...others];
  const headerSize = 12 + parts.length * 8;
  const total = parts.reduce((n, p) => n + p.data.length, headerSize);
  if (total > at.size) throw new CannotSign('the new signature does not fit');
  const out = new Uint8Array(at.size);
  put32(out, 0, CSMAGIC_EMBEDDED_SIGNATURE);
  put32(out, 4, total);
  put32(out, 8, parts.length);
  let offset = headerSize;
  parts.forEach((p, i) => {
    put32(out, 12 + i * 8, p.type);
    put32(out, 16 + i * 8, offset);
    out.set(p.data, offset);
    offset += p.data.length;
  });
  sig.set(out);
  return { was, team, identifier, entitlements: others.some((b) => b.type === CSSLOT_ENTITLEMENTS || b.type === CSSLOT_DER_ENTITLEMENTS) };
}

/**
 * Signs every slice of a file again, ad hoc — the opened one with its
 * patches, the others as they are — and says what the opened one had.
 */
export async function resignFile(file: Uint8Array, image: MachO): Promise<Resigned> {
  let opened: Resigned | undefined;
  for (const arch of image.arches) {
    const slice = file.subarray(arch.offset, arch.offset + arch.size);
    const thin = arch.offset === image.sliceOffset ? { ...image, sliceOffset: 0 } : parseMachO(slice);
    if (!thin.signatureAt) {
      if (arch.offset === image.sliceOffset) throw new CannotSign('no LC_CODE_SIGNATURE');
      continue;
    }
    const result = await resign(slice, thin);
    if (arch.offset === image.sliceOffset) opened = result;
  }
  if (!opened) throw new CannotSign('the opened slice was not found');
  return opened;
}
