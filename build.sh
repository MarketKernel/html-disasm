#!/usr/bin/env bash
# Builds build/disassembler.html, installing the tools on the first run.
#   ./build.sh           build once
#   ./build.sh --watch   rebuild on every change
#   ./build.sh open      build and open the page
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d node_modules ] || [ package-lock.json -nt node_modules ]; then
  npm ci --no-audit --no-fund
  touch node_modules
fi

if [ "${1:-}" = "open" ]; then
  node build.mjs
  open build/disassembler.html
else
  node build.mjs "$@"
fi
