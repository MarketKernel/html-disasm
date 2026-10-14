/**
 * Property lists, as an app bundle keeps its Info.plist (binary, `bplist00`,
 * as Xcode writes it) and a provisioning profile carries its contents (XML).
 * The values come out as plain JavaScript: objects, arrays, strings,
 * numbers, booleans, Dates, and Uint8Array for data.
 */

export type PlistValue = string | number | boolean | Date | Uint8Array | PlistValue[] | { [key: string]: PlistValue };

export class NotPlist extends Error {}

/** Reads a binary or XML property list. */
export function parsePlist(bytes: Uint8Array): PlistValue {
  if (bytes.length >= 8 && new TextDecoder('latin1').decode(bytes.subarray(0, 8)) === 'bplist00') return parseBinary(bytes);
  const text = new TextDecoder().decode(bytes);
  if (/<plist[\s>]/.test(text)) return parseXml(text);
  throw new NotPlist('not a property list');
}

/* ------------------------------------------------------------------ *
 * bplist00: a trailer that says where the offset table is, objects that refer to each other by number
 * ------------------------------------------------------------------ */

function parseBinary(bytes: Uint8Array): PlistValue {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 40) throw new NotPlist('truncated binary property list');
  const trailer = bytes.length - 32;
  const offsetSize = bytes[trailer + 6]!;
  const refSize = bytes[trailer + 7]!;
  const count = Number(view.getBigUint64(trailer + 8));
  const top = Number(view.getBigUint64(trailer + 16));
  const tableAt = Number(view.getBigUint64(trailer + 24));
  const uint = (at: number, size: number): number => {
    let v = 0;
    for (let i = 0; i < size; i++) v = v * 256 + bytes[at + i]!;
    return v;
  };
  const offsetOf = (ref: number) => uint(tableAt + ref * offsetSize, offsetSize);
  const depth = new Set<number>();
  const read = (ref: number): PlistValue => {
    if (ref >= count || depth.has(ref)) throw new NotPlist('a bad object reference');
    depth.add(ref);
    try {
      return object(offsetOf(ref));
    } finally {
      depth.delete(ref);
    }
  };
  // The length of an object: in the marker's low nibble, or an integer object after it when that is 0xf.
  const lengthAt = (at: number): [number, number] => {
    const low = bytes[at]! & 0xf;
    if (low !== 0xf) return [low, at + 1];
    const size = 1 << (bytes[at + 1]! & 0xf);
    return [uint(at + 2, size), at + 2 + size];
  };
  const object = (at: number): PlistValue => {
    const marker = bytes[at]!;
    const kind = marker >> 4;
    switch (kind) {
      case 0x0:
        return marker === 0x09;
      case 0x1: {
        const size = 1 << (marker & 0xf);
        if (size === 8) return Number(view.getBigInt64(at + 1));
        return uint(at + 1, size);
      }
      case 0x2:
        return (marker & 0xf) === 2 ? view.getFloat32(at + 1) : view.getFloat64(at + 1);
      case 0x3:
        // Seconds since 2001-01-01.
        return new Date((view.getFloat64(at + 1) + 978307200) * 1000);
      case 0x4: {
        const [n, start] = lengthAt(at);
        return bytes.slice(start, start + n);
      }
      case 0x5: {
        const [n, start] = lengthAt(at);
        return new TextDecoder('latin1').decode(bytes.subarray(start, start + n));
      }
      case 0x6: {
        const [n, start] = lengthAt(at);
        let s = '';
        for (let i = 0; i < n; i++) s += String.fromCharCode(view.getUint16(start + i * 2));
        return s;
      }
      case 0x8:
        return uint(at + 1, (marker & 0xf) + 1);
      case 0xa: {
        const [n, start] = lengthAt(at);
        const out: PlistValue[] = [];
        for (let i = 0; i < n; i++) out.push(read(uint(start + i * refSize, refSize)));
        return out;
      }
      case 0xd: {
        const [n, start] = lengthAt(at);
        const out: { [key: string]: PlistValue } = {};
        for (let i = 0; i < n; i++) {
          const key = read(uint(start + i * refSize, refSize));
          out[String(key)] = read(uint(start + (n + i) * refSize, refSize));
        }
        return out;
      }
    }
    throw new NotPlist(`an object of kind 0x${kind.toString(16)}`);
  };
  return read(top);
}

/* ------------------------------------------------------------------ *
 * XML
 * ------------------------------------------------------------------ */

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
const unescape = (s: string) => s.replace(/&(#x[0-9a-f]+|#\d+|\w+);/gi, (m, e: string) => (e[0] === '#' ? String.fromCodePoint(e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : Number(e.slice(1))) : ENTITIES[e] ?? m));

function parseXml(text: string): PlistValue {
  const tokens = [...text.matchAll(/<(\/?)(\w+)(?:\s[^>]*?)?(\/?)>|([^<]+)/g)];
  let k = 0;
  // Skip to the first value inside <plist>.
  while (k < tokens.length && tokens[k]![2] !== 'plist') k++;
  k++;
  const skipText = () => {
    while (k < tokens.length && tokens[k]![4] !== undefined && !tokens[k]![4]!.trim()) k++;
  };
  const textUntil = (tag: string): string => {
    let s = '';
    while (k < tokens.length && !(tokens[k]![1] === '/' && tokens[k]![2] === tag)) {
      s += tokens[k]![4] ?? '';
      k++;
    }
    k++;
    return unescape(s);
  };
  const value = (): PlistValue => {
    skipText();
    const token = tokens[k++];
    if (!token || token[1]) throw new NotPlist('unexpected end of a property list');
    const tag = token[2]!;
    const empty = token[3] === '/';
    switch (tag) {
      case 'dict': {
        const out: { [key: string]: PlistValue } = {};
        if (empty) return out;
        for (;;) {
          skipText();
          const t = tokens[k];
          if (!t || (t[1] === '/' && t[2] === 'dict')) {
            k++;
            return out;
          }
          k++;
          if (t[2] !== 'key') throw new NotPlist('a dict without a key');
          const key = textUntil('key');
          out[key] = value();
        }
      }
      case 'array': {
        const out: PlistValue[] = [];
        if (empty) return out;
        for (;;) {
          skipText();
          const t = tokens[k];
          if (!t || (t[1] === '/' && t[2] === 'array')) {
            k++;
            return out;
          }
          out.push(value());
        }
      }
      case 'string':
        return empty ? '' : textUntil('string');
      case 'integer':
        return Number(textUntil('integer').trim());
      case 'real':
        return Number(textUntil('real').trim());
      case 'true':
      case 'false':
        if (!empty) textUntil(tag);
        return tag === 'true';
      case 'date':
        return new Date(textUntil('date').trim());
      case 'data': {
        if (empty) return new Uint8Array(0);
        const b64 = textUntil('data').replace(/\s+/g, '');
        const binary = atob(b64);
        const out = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
        return out;
      }
    }
    throw new NotPlist(`an element <${tag}>`);
  };
  return value();
}

/**
 * The property list inside a provisioning profile (embedded.mobileprovision):
 * a CMS signature around an XML plist, which is found by its text.
 */
export function profilePlist(bytes: Uint8Array): PlistValue | undefined {
  const text = new TextDecoder('latin1').decode(bytes);
  const start = text.indexOf('<?xml');
  const end = text.indexOf('</plist>', start);
  if (start < 0 || end < 0) return undefined;
  try {
    return parseXml(new TextDecoder().decode(bytes.subarray(start, end + 8)));
  } catch {
    return undefined;
  }
}
