#!/bin/sh
# Builds what the tests open as 32-bit Mach-O programs. Today's Xcode still links armv7 but has
# no armv7 slice in the SDK's libraries, so the programs link with the stand-ins here (*.tbd):
# hello-armv7 from ../x86/hello.c (Thumb-2, stripped as the App Store ships it, and with its
# symbols as .full), hello-objc-armv7 from ../ios/hello.m, and hello-ios-universal with armv7 and
# arm64 slices. Xcode no longer links i386 at all: hello-i386 (stripped, starting through
# LC_UNIXTHREAD as programs before macOS 10.8 do) is linked by ld64 built from cctools-port
# (https://github.com/tpoechtrager/cctools-port, cloned and built into ../../../private), against
# a stand-in libSystem built the same way. Needs Xcode, Homebrew's llvm@21, git and make.
set -e
cd "$(dirname "$0")"
TMP=$(mktemp -d)
IOS="xcrun -sdk iphoneos clang -arch armv7 -mios-version-min=9.0 -O1 -Wall -nostdlib"
$IOS ../x86/hello.c libSystem.tbd -o hello-armv7.full
xcrun strip -o hello-armv7 hello-armv7.full
$IOS -fobjc-arc ../ios/hello.m libSystem.tbd libobjc.tbd Foundation.tbd HelloKit.tbd -o "$TMP/objc"
xcrun strip -o hello-objc-armv7 "$TMP/objc"
xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=12.0 -O1 -Wall ../x86/hello.c -o "$TMP/arm64"
xcrun strip "$TMP/arm64"
lipo -create hello-armv7 "$TMP/arm64" -output hello-ios-universal

PRIVATE=../../../private
if [ ! -x "$PRIVATE/cctools-port/cctools/ld64/src/ld/ld" ]; then
  [ -d "$PRIVATE/cctools-port" ] || git clone --depth 1 https://github.com/tpoechtrager/cctools-port.git "$PRIVATE/cctools-port"
  (cd "$PRIVATE/cctools-port/cctools" && ./configure --target=i386-apple-darwin11 CC=clang CXX=clang++ >/dev/null && make -C libstuff >/dev/null && make -C ld64 >/dev/null)
fi
LD=$PRIVATE/cctools-port/cctools/ld64/src/ld/ld
CC="$(brew --prefix llvm@21)/bin/clang --target=i386-apple-macos10.6"
# ld64 wants every dylib to link with libSystem, except libsystem_kernel: a stand-in of that comes first.
echo 'void kernel_stub(void) {}' > "$TMP/kernel.c"
$CC -c "$TMP/kernel.c" -o "$TMP/kernel.o"
$LD -arch i386 -dylib -install_name /usr/lib/system/libsystem_kernel.dylib -macosx_version_min 10.6 -o "$TMP/libsystem_kernel.dylib" "$TMP/kernel.o"
$CC -O1 -c system-i386.c -o "$TMP/system.o"
$LD -arch i386 -dylib -install_name /usr/lib/libSystem.B.dylib -macosx_version_min 10.6 -o "$TMP/libSystem.B.dylib" "$TMP/system.o" "$TMP/libsystem_kernel.dylib" 2>/dev/null
$CC -c start-i386.s -o "$TMP/start.o"
$CC -isysroot "$(xcrun --show-sdk-path)" -O1 -Wall -c ../x86/hello.c -o "$TMP/hello.o"
$LD -arch i386 -macosx_version_min 10.6 -o "$TMP/hello-i386" "$TMP/start.o" "$TMP/hello.o" "$TMP/libSystem.B.dylib"
xcrun strip -o hello-i386 "$TMP/hello-i386"
rm -rf "$TMP"
