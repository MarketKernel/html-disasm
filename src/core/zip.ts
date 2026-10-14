/**
 * Just enough of ZIP to take a native library out of an Android package
 * (.apk, .aab, .apks, .xapk — all ZIP files): the central directory lists the
 * entries, and an entry is either stored as it is (Android keeps native
 * libraries uncompressed when it may load them straight from the APK) or
 * compressed with deflate, which the browser inflates itself
 * (DecompressionStream). ZIP64 directories are read too.
 */

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  size: number;
  /** Where the entry's local header starts. */
  offset: number;
}

export const isZip = (bytes: Uint8Array): boolean => bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 3 && bytes[3] === 4;

export class NotZip extends Error {}

/** The entries of the central directory. */
export function zipEntries(bytes: Uint8Array): ZipEntry[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // The end-of-directory record is in the last 64 KiB (it may carry a comment).
  let eocd = -1;
  for (let at = bytes.length - 22; at >= Math.max(0, bytes.length - 22 - 0xffff); at--) {
    if (view.getUint32(at, true) === 0x06054b50) {
      eocd = at;
      break;
    }
  }
  if (eocd < 0) throw new NotZip('no end of central directory');
  let count = view.getUint16(eocd + 10, true);
  let dirOffset = view.getUint32(eocd + 16, true);
  // ZIP64: the locator right before the record points at the 64-bit one.
  if ((count === 0xffff || dirOffset === 0xffffffff) && eocd >= 20 && view.getUint32(eocd - 20, true) === 0x07064b50) {
    const record = Number(view.getBigUint64(eocd - 12, true));
    if (view.getUint32(record, true) === 0x06064b50) {
      count = Number(view.getBigUint64(record + 32, true));
      dirOffset = Number(view.getBigUint64(record + 48, true));
    }
  }
  const decoder = new TextDecoder();
  const entries: ZipEntry[] = [];
  let at = dirOffset;
  for (let i = 0; i < count && at + 46 <= bytes.length && view.getUint32(at, true) === 0x02014b50; i++) {
    const method = view.getUint16(at + 10, true);
    let compressedSize = view.getUint32(at + 20, true);
    let size = view.getUint32(at + 24, true);
    const nameLength = view.getUint16(at + 28, true);
    const extraLength = view.getUint16(at + 30, true);
    const commentLength = view.getUint16(at + 32, true);
    let offset = view.getUint32(at + 42, true);
    const name = decoder.decode(bytes.subarray(at + 46, at + 46 + nameLength));
    // ZIP64 extra field: the 64-bit values of the fields that overflowed, in this order.
    for (let p = at + 46 + nameLength; p + 4 <= at + 46 + nameLength + extraLength; ) {
      const id = view.getUint16(p, true);
      const length = view.getUint16(p + 2, true);
      if (id === 1) {
        let q = p + 4;
        if (size === 0xffffffff) (size = Number(view.getBigUint64(q, true))), (q += 8);
        if (compressedSize === 0xffffffff) (compressedSize = Number(view.getBigUint64(q, true))), (q += 8);
        if (offset === 0xffffffff) offset = Number(view.getBigUint64(q, true));
      }
      p += 4 + length;
    }
    entries.push({ name, method, compressedSize, size, offset });
    at += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

/** The bytes of an entry, inflated if they were deflated. */
export async function zipRead(bytes: Uint8Array, entry: ZipEntry): Promise<Uint8Array> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(entry.offset, true) !== 0x04034b50) throw new NotZip('bad local header');
  const start = entry.offset + 30 + view.getUint16(entry.offset + 26, true) + view.getUint16(entry.offset + 28, true);
  const data = bytes.subarray(start, start + entry.compressedSize);
  if (entry.method === 0) return data;
  if (entry.method !== 8) throw new NotZip(`compression method ${entry.method}`);
  const stream = new Blob([data as Uint8Array<ArrayBuffer>]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** A native library in an Android package: lib/<abi>/name.so (base/lib/… in an .aab). */
export interface PackagedLibrary {
  abi: string;
  file: string;
  size: number;
  /** The split APK it is in, for an .apks or .xapk bundle. */
  from?: string;
  read(): Promise<Uint8Array>;
}

const LIBRARY = /(?:^|\/)lib\/([^/]+)\/([^/]+\.so)$/;

/**
 * The native libraries of a package. An .apk or .aab has them under lib/<abi>/; a bundle of
 * split APKs (.apks from bundletool, .xapk, .apkm) has them in the APKs inside it — usually one
 * per ABI, split_config.arm64_v8a.apk — which are opened in turn.
 */
export async function packagedLibraries(bytes: Uint8Array): Promise<PackagedLibrary[]> {
  const out: PackagedLibrary[] = [];
  const entries = zipEntries(bytes);
  for (const entry of entries) {
    const match = LIBRARY.exec(entry.name);
    if (match) out.push({ abi: match[1]!, file: match[2]!, size: entry.size, read: () => zipRead(bytes, entry) });
  }
  for (const entry of entries) {
    if (!/\.apk$/i.test(entry.name)) continue;
    const inner = await zipRead(bytes, entry);
    if (!isZip(inner)) continue;
    const from = entry.name.split('/').pop()!;
    for (const lib of zipEntries(inner)) {
      const match = LIBRARY.exec(lib.name);
      if (match) out.push({ abi: match[1]!, file: match[2]!, size: lib.size, from, read: () => zipRead(inner, lib) });
    }
  }
  return out;
}
