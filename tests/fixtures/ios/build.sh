#!/bin/sh
# Builds what the iOS tests open: Hello.ipa, an app for arm64 iOS with an Objective-C executable
# (hello.m) and a Swift framework (HelloKit.swift), each with its Info.plist (binary, as Xcode
# writes them); and the executable on its own, stripped as the App Store ships it — once more as
# HelloClassic, linked with dyld's older bind opcodes instead of chained fixups. Needs Xcode.
set -e
cd "$(dirname "$0")"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
TMP=$(mktemp -d)
APP="$TMP/Payload/Hello.app"
mkdir -p "$APP/Frameworks/HelloKit.framework"
xcrun -sdk iphoneos swiftc -target arm64-apple-ios15.0 -O -emit-library -module-name HelloKit \
  -Xlinker -install_name -Xlinker @rpath/HelloKit.framework/HelloKit -o "$APP/Frameworks/HelloKit.framework/HelloKit" HelloKit.swift
xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=15.0 -O1 -fobjc-arc -framework Foundation \
  -F "$APP/Frameworks" "$APP/Frameworks/HelloKit.framework/HelloKit" -Wl,-rpath,@executable_path/Frameworks -o "$APP/Hello" hello.m
xcrun strip -x "$APP/Hello"
cp "$APP/Hello" Hello
xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=15.0 -O1 -fobjc-arc -framework Foundation \
  "$APP/Frameworks/HelloKit.framework/HelloKit" -Wl,-no_fixup_chains -o HelloClassic hello.m
xcrun strip -x HelloClassic
plist() {
  /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string $2" -c "Add :CFBundleExecutable string $3" -c "Add :CFBundleName string $3" \
    -c "Add :CFBundleShortVersionString string 1.2" -c "Add :CFBundleVersion string 34" -c "Add :CFBundlePackageType string $4" \
    -c "Add :MinimumOSVersion string 15.0" -c "Add :CFBundleSupportedPlatforms array" -c "Add :CFBundleSupportedPlatforms:0 string iPhoneOS" "$1" >/dev/null
  plutil -convert binary1 "$1"
}
plist "$APP/Info.plist" com.example.hello Hello APPL
/usr/libexec/PlistBuddy -c "Add :UIDeviceFamily array" -c "Add :UIDeviceFamily:0 integer 1" -c "Add :UIDeviceFamily:1 integer 2" "$APP/Info.plist" >/dev/null
plist "$APP/Frameworks/HelloKit.framework/Info.plist" com.example.hellokit HelloKit FMWK
find "$TMP" -exec touch -t 202601010000 {} +
rm -f Hello.ipa
(cd "$TMP" && zip -q -X -r -9 Hello.ipa Payload)
mv "$TMP/Hello.ipa" .
rm -rf "$TMP"
