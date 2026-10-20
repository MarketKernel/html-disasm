#!/usr/bin/env bash
# Builds build/disassembler.html: the core's WebAssembly module first (tools/wasm.mjs, Rust), then
# the page around it, installing the npm tools on the first run.
#   ./build.sh           build once
#   ./build.sh --watch   build the core once, then rebuild the page on every change under src/
#                        and assets/ (a change to crates/ needs ./build.sh again)
#   ./build.sh open      build and open the page
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d node_modules ] || [ package-lock.json -nt node_modules ]; then
  npm ci --no-audit --no-fund
  touch node_modules
fi

# The core is Rust, built for wasm32-unknown-unknown: say what is missing before Cargo does, less plainly.
if ! command -v cargo >/dev/null; then
  echo "Rust is needed to build the core: https://rustup.rs" >&2
  exit 1
fi
if command -v rustup >/dev/null && ! rustup target list --installed | grep -qx wasm32-unknown-unknown; then
  echo "The WebAssembly target is missing: rustup target add wasm32-unknown-unknown" >&2
  exit 1
fi
node tools/wasm.mjs

if [ "${1:-}" = "open" ]; then
  node build.mjs
  open build/disassembler.html
else
  node build.mjs "$@"
fi
