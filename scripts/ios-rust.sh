#!/bin/sh
# Build the Rust vault core (crates/stash-ffi) for iPhone and the iOS
# simulator, and package both as ios/StashCore.xcframework for the app.
set -eu

cd "$(dirname "$0")/.."
# Xcode (not just the Command Line Tools) has the iOS SDKs.
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
export IPHONEOS_DEPLOYMENT_TARGET=17.0

for target in aarch64-apple-ios aarch64-apple-ios-sim; do
    rustup target add "$target" >/dev/null 2>&1 || true
    cargo build --release --locked -p stash-ffi --target "$target"
done

out=ios/build
rm -rf "$out/headers" ios/StashCore.xcframework
mkdir -p "$out/headers"
cp crates/stash-ffi/include/stash.h "$out/headers/"
cat > "$out/headers/module.modulemap" <<MAP
module StashCore {
    header "stash.h"
    export *
}
MAP

xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libstash_ffi.a -headers "$out/headers" \
    -library target/aarch64-apple-ios-sim/release/libstash_ffi.a -headers "$out/headers" \
    -output ios/StashCore.xcframework >/dev/null
echo "Built ios/StashCore.xcframework"
