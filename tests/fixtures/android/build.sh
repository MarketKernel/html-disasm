#!/bin/sh
# Builds what the tests open: the library for armeabi-v7a (Thumb-2, with arm.c in A32) and
# arm64-v8a, each stripped as an APK carries it; the armeabi-v7a one also with its symbol
# table (.full.so), whose mapping symbols the tests check the stripped analysis against;
# hello.apk holding both, one entry stored and one deflated; and hello.apks, the same as a
# bundle of split APKs. Needs the Android NDK (ANDROID_NDK, or the newest one in the SDK) and zip.
set -e
cd "$(dirname "$0")"
NDK=${ANDROID_NDK:-$(ls -d "$HOME"/Library/Android/sdk/ndk/* | sort -V | tail -1)}
BIN=$(ls -d "$NDK"/toolchains/llvm/prebuilt/*/bin | head -1)
FLAGS="-O1 -fPIC -Wall -Wextra"
TMP=$(mktemp -d)
"$BIN/armv7a-linux-androideabi21-clang" $FLAGS -marm -c arm.c -o "$TMP/arm.o"
"$BIN/armv7a-linux-androideabi21-clang" $FLAGS -mthumb -shared -o libhello-armeabi-v7a.full.so hello.c "$TMP/arm.o" -llog
"$BIN/aarch64-linux-android21-clang" $FLAGS -shared -o "$TMP/libhello-arm64-v8a.so" hello.c arm.c -llog
"$BIN/llvm-strip" --strip-unneeded -o libhello-armeabi-v7a.so libhello-armeabi-v7a.full.so
"$BIN/llvm-strip" --strip-unneeded -o libhello-arm64-v8a.so "$TMP/libhello-arm64-v8a.so"
mkdir -p "$TMP/apk/lib/armeabi-v7a" "$TMP/apk/lib/arm64-v8a" "$TMP/apks/splits" "$TMP/v7/lib/armeabi-v7a" "$TMP/v8/lib/arm64-v8a"
cp libhello-armeabi-v7a.so "$TMP/apk/lib/armeabi-v7a/libhello.so"
cp libhello-arm64-v8a.so "$TMP/apk/lib/arm64-v8a/libhello.so"
cp libhello-armeabi-v7a.so "$TMP/v7/lib/armeabi-v7a/libhello.so"
cp libhello-arm64-v8a.so "$TMP/v8/lib/arm64-v8a/libhello.so"
echo '<manifest package="com.example.hello"/>' > "$TMP/apk/AndroidManifest.xml"
# The archives keep the files' times: a fixed one keeps them the same from build to build.
stamp() { find "$TMP" -type f -exec touch -t 202601010000 {} +; }
stamp
rm -f hello.apk hello.apks
(cd "$TMP/apk" && zip -q -X -0 "$TMP/hello.apk" lib/armeabi-v7a/libhello.so && zip -q -X -9 "$TMP/hello.apk" lib/arm64-v8a/libhello.so AndroidManifest.xml)
# hello.apks: what bundletool makes for a device, a base APK and one split APK per ABI.
(cd "$TMP/apk" && zip -q -X -9 "$TMP/apks/splits/base-master.apk" AndroidManifest.xml)
(cd "$TMP/v7" && zip -q -X -0 "$TMP/apks/splits/split_config.armeabi_v7a.apk" lib/armeabi-v7a/libhello.so)
(cd "$TMP/v8" && zip -q -X -0 "$TMP/apks/splits/split_config.arm64_v8a.apk" lib/arm64-v8a/libhello.so)
stamp
(cd "$TMP/apks" && zip -q -X -0 "$TMP/hello.apks" splits/base-master.apk splits/split_config.armeabi_v7a.apk splits/split_config.arm64_v8a.apk)
mv "$TMP/hello.apk" "$TMP/hello.apks" .
rm -rf "$TMP"
