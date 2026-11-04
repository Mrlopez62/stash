#!/bin/sh
# Build the stash iPhone app: the Rust core, the Xcode project (XcodeGen),
# then the app. With no arguments it builds for the iOS simulator (no
# signing needed); scripts/ios-install.sh builds for your iPhone.
set -eu

cd "$(dirname "$0")/.."
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
command -v xcodegen >/dev/null || { echo "Needs XcodeGen: brew install xcodegen"; exit 1; }

./scripts/ios-rust.sh
STASH_TEAM_ID="${STASH_TEAM_ID:-}" xcodegen --spec ios/project.yml --quiet
xcodebuild -project ios/Stash.xcodeproj -scheme Stash \
    -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath ios/build/DerivedData \
    CODE_SIGNING_ALLOWED=NO -quiet build
echo "Built ios/build/DerivedData/Build/Products/Debug-iphonesimulator/Stash.app"
