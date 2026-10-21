# Contributing to stash

Thanks for helping out! stash is a secrets manager, so we care about correctness and security more than speed. This guide explains how to get a change merged.

## Ground rules

- **Found a security problem? Don't open a public issue.** Follow [SECURITY.md](SECURITY.md).
- Be kind. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- For anything bigger than a small fix, open an issue first so we can agree on the approach before you write the code.

## Branches

- `main` is the stable branch. Never commit to it directly.
- `dev` is where development happens. Branch from `dev` and open your pull request against `dev`.
- Maintainers move `dev` into `main` with a pull request when it's ready to release.

## Setup

You need [Rust](https://rustup.rs) 1.88 or newer.

```sh
git clone https://github.com/Mrlopez62/stash.git
cd stash
git checkout dev
cargo test
```

On macOS, also build the Touch ID helper (needs Xcode or the Command Line Tools):

```sh
swift build -c release --package-path swift/stash-touchid
```

The tests don't need a fingerprint. They use a fake helper (see `fake_touch_id` in `crates/stash-cli/tests/cli.rs` and `tests/mcp.rs`), so they run anywhere. `tests/mcp.rs` drives `stash mcp` over stdio the way a real MCP client does. Changes to the Swift helper itself need a manual check on a Mac with Touch ID.

### The Mac app

The app lives in `macos/StashApp`, a Swift package. It's UI only: it runs `stash app-server` (`crates/stash-cli/src/app_server.rs`) and talks JSON-RPC to it.

```sh
./scripts/build-app.sh                          # build/stash.app
swift build --package-path macos/StashApp       # just the app, for quick iteration
```

- **No `@State`.** Use `@ViewState` (see `ViewState.swift`). The SwiftUI `@State` macro's plugin ships only with Xcode, and stash builds with the Command Line Tools alone.
- **Check the UI without touching a vault.** Render the window from sample data:
  ```sh
  macos/StashApp/.build/debug/Stash --mock --snapshot /tmp/shot.png [--select github] [--locked] [--quick-access]
  ```
- **Check the Swift ↔ Rust protocol** against a throwaway vault:
  ```sh
  STASH_VAULT=/tmp/selftest.db build/stash.app/Contents/MacOS/Stash --selftest
  ```

Try the CLI against a throwaway vault so you don't touch your real one:

```sh
export STASH_VAULT=/tmp/stash-dev.db STASH_AGENT_SOCK=/tmp/stash-dev.sock
cargo run -- init
echo "hello" | cargo run -- add demo/secret
cargo run -- get demo/secret
```

## Before you open a pull request

CI runs these same checks, so run them locally first:

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
node --test browser/test/fill.test.mjs browser/test/background.test.mjs
```

- **Run tests in debug builds** (plain `cargo test`, not `--release`). Release builds ignore the test-only overrides (`STASH_TOUCHID_HELPER`, `STASH_AI_AGENTS`), so with an AI agent such as Claude Code running on your machine, sessions would pause and the session tests would fail.
- **Add tests.** Bug fixes need a test that fails without the fix. New behavior needs tests that cover it.
- **Keep it focused.** One logical change per pull request.
- **Update the changelog.** Add a line to `docs/CHANGELOG.md` for anything users would notice.
- **Write clear commit messages.** Use an imperative subject line of 72 characters or fewer, like "Add `stash rm` confirmation".

## Rules for security-sensitive code

These apply to everything in `crates/stash-core` and any code that touches secret values:

- **Never log, print, or `Debug`-format a secret value.** Wrap secrets in `Zeroizing` or `secrecy` types.
- **Don't write your own crypto.** Use the audited [RustCrypto](https://github.com/RustCrypto) crates the project already depends on. Adding a new crypto dependency needs discussion in an issue first.
- **Version the vault format.** Any change to the on-disk format must bump `FORMAT_VERSION` and include a migration path. Existing vaults must keep opening.
- **Update the threat model.** If a change affects what stash protects against, update [docs/threat-model.md](threat-model.md).

## Project layout

```
crates/stash-core   vault format, crypto, and operations (library)
crates/stash-cli    the `stash` command and session agent
swift/stash-touchid Touch ID helper (macOS)
macos/StashApp      the Mac app (SwiftUI)
scripts/            install script
docs/               design and security docs
```

## License

By contributing, you agree that your contributions are licensed under the [MIT License](../LICENSE).
