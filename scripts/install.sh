#!/bin/sh
# Build and install `stash`, plus the Touch ID helper on macOS.
# Both go in Cargo's bin directory (usually ~/.cargo/bin), side by side,
# which is where `stash` looks for the helper. The helper is a small app
# bundle (stash-touchid.app), so Touch ID prompts show the stash icon.
set -eu

cd "$(dirname "$0")/.."
bin_dir="${CARGO_HOME:-$HOME/.cargo}/bin"

cargo install --path crates/stash-cli --locked

if [ "$(uname -s)" = "Darwin" ]; then
    swift build -c release --package-path swift/stash-touchid
    ./scripts/helper-bundle.sh "$bin_dir"
    # The helper used to be a bare executable here.
    rm -f "$bin_dir/stash-touchid"
    echo "Installed stash and stash-touchid.app to $bin_dir"
else
    echo "Installed stash to $bin_dir (Touch ID is macOS-only)"
fi
