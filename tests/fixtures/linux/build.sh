#!/bin/sh
# Builds what the tests open as Linux Arm programs, from ../x86/hello.c: one for arm64 and two
# for armhf (glibc, zig cc), all stripped. zig's armhf code is A32; Debian and Ubuntu build
# Thumb-2, so there is a Thumb one too (zig ignores -mthumb; the target feature does it), whose
# _start, from glibc's crt1, stays A32. The armhf ones are also kept with their symbol table
# (.full), whose mapping symbols the tests check the stripped layout against. Needs zig and
# Homebrew's llvm@21 (llvm-strip).
set -e
cd "$(dirname "$0")"
STRIP=$(brew --prefix llvm@21)/bin/llvm-strip
FLAGS="-O1 -Wall -Wextra"
zig cc -target aarch64-linux-gnu $FLAGS -s -o hello-linux-arm64 ../x86/hello.c
zig cc -target arm-linux-gnueabihf $FLAGS -o hello-linux-armhf.full ../x86/hello.c
zig cc -target arm-linux-gnueabihf -Xclang -target-feature -Xclang +thumb-mode $FLAGS -o hello-linux-armhf-thumb.full ../x86/hello.c
for f in hello-linux-armhf hello-linux-armhf-thumb; do
  "$STRIP" --strip-debug $f.full
  "$STRIP" --strip-all -o $f $f.full
done
