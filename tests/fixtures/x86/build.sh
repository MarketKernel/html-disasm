#!/bin/sh
# Builds what the x86 tests open from hello.c: Linux programs for x86-64 and i386 (zig cc,
# glibc), Windows programs for x86-64 and i386 and a DLL (zig cc, MinGW), Android libraries
# for x86_64 and x86 (the NDK, stripped as in an APK), a universal macOS program with
# x86_64 and arm64 slices (clang), and a C++ DLL with MSVC's names (msvc.cpp, Homebrew's
# llvm@21 clang and lld@21 lld-link, importing from the C++ runtime by name through
# vcruntime.def and msvcp.def). Needs zig, the Android NDK (ANDROID_NDK, or the newest one in
# the SDK), Xcode's clang and Homebrew's llvm@21 and lld@21.
set -e
cd "$(dirname "$0")"
NDK=${ANDROID_NDK:-$(ls -d "$HOME"/Library/Android/sdk/ndk/* | sort -V | tail -1)}
BIN=$(ls -d "$NDK"/toolchains/llvm/prebuilt/*/bin | head -1)
FLAGS="-O1 -Wall -Wextra"
zig cc -target x86_64-linux-gnu $FLAGS -s -o hello-linux-x86_64 hello.c
zig cc -target x86-linux-gnu $FLAGS -s -o hello-linux-i386 hello.c
zig cc -target x86_64-windows-gnu $FLAGS -s -o hello-x64.exe hello.c
zig cc -target x86-windows-gnu $FLAGS -s -o hello-x86.exe hello.c
zig cc -target x86_64-windows-gnu $FLAGS -s -shared -Wl,--export-all-symbols -o hello-x64.dll hello.c
rm -f hello.lib hello-x64.lib hello-x64.pdb hello-x64.exe.pdb hello-x86.exe.pdb
"$BIN/x86_64-linux-android21-clang" $FLAGS -fPIC -shared -Wl,--build-id=none -o libhello-x86_64.so hello.c
"$BIN/i686-linux-android21-clang" $FLAGS -fPIC -shared -Wl,--build-id=none -o libhello-x86.so hello.c
"$BIN/llvm-strip" --strip-unneeded libhello-x86_64.so libhello-x86.so
clang $FLAGS -arch x86_64 -arch arm64 -o hello-macos hello.c
LLVM=$(brew --prefix llvm@21)/bin
LINK=$(brew --prefix lld@21)/bin/lld-link
TMP=$(mktemp -d)
"$LLVM/clang++" --target=x86_64-pc-windows-msvc -O1 -fno-exceptions -fno-rtti -c msvc.cpp -o "$TMP/msvc.obj"
"$LINK" /lib /def:vcruntime.def /machine:x64 /out:"$TMP/vcruntime.lib"
"$LINK" /lib /def:msvcp.def /machine:x64 /out:"$TMP/msvcp.lib"
"$LINK" /dll /noentry /nodefaultlib /brepro /out:"$TMP/hello-msvc.dll" "$TMP/msvc.obj" "$TMP/vcruntime.lib" "$TMP/msvcp.lib"
cp "$TMP/hello-msvc.dll" .
rm -rf "$TMP"
