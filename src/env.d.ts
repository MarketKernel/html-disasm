/** package.json's version, as build.mjs puts it in: 0.1.0, or 0.1.0+1a2b3c4 off a release. */
declare const __APP_VERSION__: string;

/** A file as a string, by tools/text-plugin.mjs. */
declare module '*?text' {
  const text: string;
  export default text;
}

/** A file's bytes, by esbuild's binary loader: the core's WebAssembly module. */
declare module '*.wasm' {
  const bytes: Uint8Array;
  export default bytes;
}
