## What does this change?

<!-- A short summary. Link the issue it closes, e.g. "Closes #12". -->

## How was it tested?

<!-- New or updated tests, plus any manual steps. -->

## Checklist

- [ ] The pull request targets `dev`, not `main` (unless this is a release PR from `dev`)
- [ ] `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` pass
- [ ] No secret values are logged, printed, or `Debug`-formatted
- [ ] Vault format changes bump `FORMAT_VERSION` and include a migration
- [ ] `docs/threat-model.md` is updated if the security model changed
