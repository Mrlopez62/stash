#!/bin/sh
# Wrap the Touch ID helper in a small app bundle, stash-touchid.app, inside
# the given directory (next to the `stash` that uses it).
#
# macOS shows the icon and name of the program asking for a fingerprint. A
# bare executable gets a generic terminal icon and its file name
# ("stash-touchid is trying to..."); inside a bundle named "stash" with the
# stash icon, every Touch ID prompt is recognizably stash's.
#
#   ./scripts/helper-bundle.sh <dir>   # needs the helper built (swift build -c release)
set -eu

cd "$(dirname "$0")/.."
dest="$1"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
bundle="$dest/stash-touchid.app"

rm -rf "$bundle"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
install -m 755 swift/stash-touchid/.build/release/stash-touchid "$bundle/Contents/MacOS/stash-touchid"
cp macos/StashApp/Resources/AppIcon.icns "$bundle/Contents/Resources/AppIcon.icns"

cat > "$bundle/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>io.github.mrlopez62.stash.touchid</string>
    <key>CFBundleName</key><string>stash</string>
    <key>CFBundleDisplayName</key><string>stash</string>
    <key>CFBundleExecutable</key><string>stash-touchid</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$version</string>
    <key>CFBundleVersion</key><string>$version</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <!-- A helper: never in the Dock or the app switcher. -->
    <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST

# Ad-hoc signature, sealing the bundle (Info.plist and icon included).
codesign --force --sign - "$bundle"
codesign --verify --strict "$bundle"
