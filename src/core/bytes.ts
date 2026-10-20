/** Reading the encodings several file formats share: UTF-8 text and LEB128 numbers. */

const decoder = new TextDecoder('utf-8', { fatal: false });

/** Bytes as UTF-8 text; what does not decode becomes U+FFFD. */
export const utf8 = (bytes: Uint8Array): string => decoder.decode(bytes);

/** An unsigned LEB128 number at `at`, and where it ends; it stops at the end of the bytes. */
export function uleb(bytes: Uint8Array, at: number): [number, number] {
  let result = 0;
  let shift = 0;
  let p = at;
  for (;;) {
    const byte = bytes[p++] ?? 0;
    result += (byte & 0x7f) * 2 ** shift;
    shift += 7;
    if (!(byte & 0x80) || p >= bytes.length) break;
  }
  return [result, p];
}

/** A signed LEB128 number at `at`, and where it ends. */
export function sleb(bytes: Uint8Array, at: number): [number, number] {
  let result = 0;
  let shift = 0;
  let p = at;
  let byte = 0;
  do {
    byte = bytes[p++] ?? 0;
    result += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  } while (byte & 0x80 && p < bytes.length);
  if (byte & 0x40) result -= 2 ** shift;
  return [result, p];
}
