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

Try the CLI against a throwaway vault so you don't touch your real one:

```sh
export STASH_VAULT=/tmp/stash-dev.db
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
```

- **Add tests.** Bug fixes need a test that fails without the fix. New behavior needs tests that cover it.
- **Keep it focused.** One logical change per pull request.
- **Write clear commit messages.** Use an imperative subject line of 72 characters or fewer, like "Add `stash rm` confirmation".

## Rules for security-sensitive code

These apply to everything in `crates/stash-core` and any code that touches secret values:

- **Never log, print, or `Debug`-format a secret value.** Wrap secrets in `Zeroizing` or `secrecy` types.
- **Don't write your own crypto.** Use the audited [RustCrypto](https://github.com/RustCrypto) crates the project already depends on. Adding a new crypto dependency needs discussion in an issue first.
- **Version the vault format.** Any change to the on-disk format must bump `FORMAT_VERSION` and include a migration path. Existing vaults must keep opening.
- **Update the threat model.** If a change affects what stash protects against, update [docs/threat-model.md](docs/threat-model.md).

## Project layout

```
crates/stash-core   vault format, crypto, and operations (library)
crates/stash-cli    the `stash` command
docs/               design and security docs
```

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
