#!/bin/sh
# Build stash.app: the Mac app with the stash CLI and Touch ID helper inside.
# Needs Rust and the Xcode Command Line Tools (not Xcode itself).
#
#   ./scripts/build-app.sh            # build build/stash.app
#   ./scripts/build-app.sh --install  # and copy it to ~/Applications
set -eu

cd "$(dirname "$0")/.."
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
app=build/stash.app

echo "Building stash $version"
cargo build --release --locked -p stash-cli
swift build -c release --package-path swift/stash-touchid
swift build -c release --package-path macos/StashApp

rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Helpers" "$app/Contents/Resources"
cp macos/StashApp/.build/release/Stash "$app/Contents/MacOS/Stash"
cp target/release/stash "$app/Contents/Helpers/stash"
cp swift/stash-touchid/.build/release/stash-touchid "$app/Contents/Helpers/stash-touchid"
cp macos/StashApp/Resources/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
# Brand fonts (SIL Open Font License; the licenses ship alongside).
mkdir -p "$app/Contents/Resources/Fonts"
cp macos/StashApp/Sources/Stash/Fonts/* "$app/Contents/Resources/Fonts/"

cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>io.github.mrlopez62.stash</string>
    <key>CFBundleName</key><string>stash</string>
    <key>CFBundleDisplayName</key><string>stash</string>
    <key>CFBundleExecutable</key><string>Stash</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$version</string>
    <key>CFBundleVersion</key><string>$version</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.productivity</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSHumanReadableCopyright</key><string>MIT License</string>
</dict>
</plist>
PLIST

# Ad-hoc signature: free, and enough for Touch ID's Secure Enclave keys.
# Helpers first, then the app, so the bundle's seal covers them.
codesign --force --sign - "$app/Contents/Helpers/stash"
codesign --force --sign - "$app/Contents/Helpers/stash-touchid"
codesign --force --sign - "$app"
codesign --verify --strict "$app"
echo "Built $app"

if [ "${1:-}" = "--install" ]; then
    mkdir -p "$HOME/Applications"
    rm -rf "$HOME/Applications/stash.app"
    cp -R "$app" "$HOME/Applications/stash.app"
    echo "Installed to ~/Applications/stash.app"
fi
