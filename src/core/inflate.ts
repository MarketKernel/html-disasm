/** Inflates what tools/x86-index.mjs deflated into base64 (the x86 tables), with the browser's own DecompressionStream. */
export async function inflateBase64(base64: string): Promise<Uint8Array> {
  const binary = atob(base64);
  const packed = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) packed[i] = binary.charCodeAt(i);
  const stream = new Blob([packed]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
