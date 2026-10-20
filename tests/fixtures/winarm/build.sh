#!/bin/sh
# Builds what the Windows-on-Arm tests open: ../x86/hello.c for arm64 and for 32-bit Arm (Thumb-2)
# with zig (MinGW), and two hybrid libraries with clang and lld-link 21 (Homebrew's llvm@21 and
# lld@21): arm64ec.dll, ARM64EC code (ec.c) beside x64 code (x64.c), and arm64x.dll, the same
# with plain arm64 code (native.c) for Arm processes. chpe-*.s stand in for what MSVC's runtime
# gives a hybrid image. imports-arm64.dll and imports-arm.dll call functions of another DLL
# through its import address table, as MSVC compiles them (imports.c, dep.def).
set -e
cd "$(dirname "$0")"
LLVM=${LLVM:-/opt/homebrew/opt/llvm@21/bin}
LLD=${LLD:-/opt/homebrew/opt/lld@21/bin}
zig cc -target aarch64-windows-gnu -O1 -s -o hello-arm64.exe ../x86/hello.c
zig cc -target thumb-windows-gnu -O1 -s -o hello-arm.exe ../x86/hello.c
rm -f hello-arm64.pdb hello-arm.pdb
TMP=$(mktemp -d)
"$LLVM/clang" --target=arm64ec-pc-windows-msvc -c chpe-ec.s -o "$TMP/chpe-ec.obj"
"$LLVM/clang" --target=aarch64-pc-windows-msvc -c chpe-arm64.s -o "$TMP/chpe-arm64.obj"
"$LLVM/clang" --target=arm64ec-pc-windows-msvc -O1 -c ec.c -o "$TMP/ec.obj"
"$LLVM/clang" --target=x86_64-pc-windows-msvc -O1 -fno-builtin -c x64.c -o "$TMP/x64.obj"
"$LLVM/clang" --target=aarch64-pc-windows-msvc -O1 -c native.c -o "$TMP/native.obj"
"$LLD/lld-link" /dll /noentry /machine:arm64ec /brepro /noimplib "$TMP/ec.obj" "$TMP/x64.obj" "$TMP/chpe-ec.obj" /out:arm64ec.dll
"$LLD/lld-link" /dll /noentry /machine:arm64x /brepro /noimplib "$TMP/ec.obj" "$TMP/x64.obj" "$TMP/chpe-ec.obj" "$TMP/native.obj" "$TMP/chpe-arm64.obj" /out:arm64x.dll
"$LLVM/llvm-dlltool" -m arm64 -d dep.def -l "$TMP/dep-arm64.lib"
"$LLVM/llvm-dlltool" -m arm -d dep.def -l "$TMP/dep-arm.lib"
"$LLVM/clang" --target=aarch64-pc-windows-msvc -O1 -c imports.c -o "$TMP/imports-arm64.obj"
"$LLVM/clang" --target=thumbv7-pc-windows-msvc -O1 -c imports.c -o "$TMP/imports-arm.obj"
"$LLD/lld-link" /dll /noentry /machine:arm64 /brepro /noimplib "$TMP/imports-arm64.obj" "$TMP/dep-arm64.lib" /out:imports-arm64.dll
"$LLD/lld-link" /dll /noentry /machine:arm /brepro /noimplib "$TMP/imports-arm.obj" "$TMP/dep-arm.lib" /out:imports-arm.dll
rm -rf "$TMP"
