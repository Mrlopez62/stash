#!/bin/sh
# Build the stash iPhone app and install it on your iPhone, signed with your
# own (free) Apple ID. With a free Apple ID, Apple lets the app open for 7
# days; run this again to renew it. Your vault on the phone is kept.
#
# Once:
#   1. Xcode → Settings → Accounts → + → sign in with your Apple ID.
#   2. Plug in your iPhone (unlocked) and tap Trust on it.
#   3. On the iPhone: Settings → Privacy & Security → Developer Mode → On.
# Then:
#   ./scripts/ios-install.sh
# The first time, the iPhone asks you to trust the developer: Settings →
# General → VPN & Device Management → your Apple ID → Trust.
set -eu

cd "$(dirname "$0")/.."
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
command -v xcodegen >/dev/null || { echo "Needs XcodeGen: brew install xcodegen"; exit 1; }

# Your team: from the "Apple Development" certificate Xcode made for your
# Apple ID (its OU), unless STASH_TEAM_ID says otherwise.
if [ -z "${STASH_TEAM_ID:-}" ]; then
    STASH_TEAM_ID=$(security find-certificate -a -c "Apple Development" -p 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null \
        | sed -n 's/.*OU *= *\([A-Z0-9]\{10\}\).*/\1/p' | head -1)
fi
if [ -z "$STASH_TEAM_ID" ]; then
    echo "No Apple Development certificate found. In Xcode: Settings → Accounts → + → sign in with your Apple ID,"
    echo "then select it and click Manage Certificates → + → Apple Development. Or set STASH_TEAM_ID."
    exit 1
fi
export STASH_TEAM_ID

./scripts/ios-rust.sh
xcodegen --spec ios/project.yml --quiet

# A real iPhone (simulators are listed too, as "simulated").
device=$(xcrun devicectl list devices 2>/dev/null | awk '/iPhone/ && /(available|connected)/ && !/simulated/ { for (i = 1; i <= NF; i++) if ($i ~ /^[0-9A-F]{8}-/) { print $i; exit } }')
if [ -z "$device" ]; then
    echo "No iPhone found. Plug it in, unlock it, tap Trust, and turn on Developer Mode."
    exit 1
fi

xcodebuild -project ios/Stash.xcodeproj -scheme Stash -configuration Release \
    -destination 'generic/platform=iOS' -derivedDataPath ios/build/DerivedData \
    -allowProvisioningUpdates -allowProvisioningDeviceRegistration \
    DEVELOPMENT_TEAM="$STASH_TEAM_ID" -quiet build
xcrun devicectl device install app --device "$device" \
    ios/build/DerivedData/Build/Products/Release-iphoneos/Stash.app
echo "Installed stash on your iPhone. With a free Apple ID, run this again within 7 days to keep it opening."
