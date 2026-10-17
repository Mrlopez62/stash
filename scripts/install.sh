#!/bin/sh
# Build and install `stash`, plus the Touch ID helper on macOS.
# Both go in Cargo's bin directory (usually ~/.cargo/bin), side by side,
# which is where `stash` looks for the helper.
set -eu

cd "$(dirname "$0")/.."
bin_dir="${CARGO_HOME:-$HOME/.cargo}/bin"

cargo install --path crates/stash-cli --locked

if [ "$(uname -s)" = "Darwin" ]; then
    swift build -c release --package-path swift/stash-touchid
    install -m 755 swift/stash-touchid/.build/release/stash-touchid "$bin_dir/stash-touchid"
    echo "Installed stash and stash-touchid to $bin_dir"
else
    echo "Installed stash to $bin_dir (Touch ID is macOS-only)"
fi
