<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/logo-dark.svg">
    <img src="docs/brand/logo-light.svg" alt="stash" width="340">
  </picture>
</h1>

<p align="center"><strong>Your secrets, one fingerprint away.</strong></p>

<p align="center">
  <a href="https://github.com/Mrlopez62/stash/actions/workflows/ci.yml"><img src="https://github.com/Mrlopez62/stash/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-F5B544.svg?labelColor=0E1116" alt="License: MIT"></a>
</p>

A free, developer-first secrets manager for macOS. Unlock with Touch ID, pass API tokens into commands safely, and let AI agents use your secrets without ever seeing them.

> **Status: early development (v0.3).** The encrypted vault, the CLI, Touch ID unlock, unlocked sessions, `stash://` references, `stash run`, and `stash inject` work today. MCP support for AI agents is next (see [Roadmap](#roadmap)). Don't trust it with production secrets until it has been reviewed.

## Getting started

Requires [Rust](https://rustup.rs) 1.88 or newer. On macOS, the Touch ID helper also needs Xcode or the Command Line Tools (`xcode-select --install`).

```sh
git clone https://github.com/Mrlopez62/stash.git
cd stash
./scripts/install.sh                  # installs `stash` (and `stash-touchid` on macOS)

stash init                            # create a vault (asks for a new master password)
stash touchid enable                  # macOS: unlock with your fingerprint from now on
stash add github/token                # prompts for the value without echoing it
echo "$OPENAI_KEY" | stash add openai/api-key   # or pipe it in
stash ls                              # names only
stash get github/token                # prints the value
stash rm github/token
stash lock                            # end the unlocked session now
```

How unlocking works:
- **The first command unlocks the vault.** With Touch ID turned on, that's a fingerprint prompt. Otherwise you type the master password. If Touch ID is cancelled or unavailable (for example, the lid is closed), stash asks for the master password instead.
- **Then a session starts, for that terminal only.** stash commands you run from the same shell in the next **10 minutes** don't ask again, and each use restarts the 10-minute timer. A small background agent holds the session, like `ssh-agent`. Run `stash lock` to end it early.
- **Everything else has to ask.** That includes commands started by `stash run`, scripts, other terminals, and AI agents. They all get their own Touch ID prompt, which says what they want and who is asking, for example: *stash-touchid is trying to unlock stash for “get stripe/secret”, requested by sh ← stash*.

| Setting | What it does |
|---|---|
| `--vault <path>` / `STASH_VAULT` | Use a vault other than `~/.stash/vault.db` |
| `STASH_SESSION_TIMEOUT` | How many seconds a session lasts without use. `0` turns sessions off |
| `STASH_PASSWORD` | Supply the master password for scripts and CI. This skips Touch ID and sessions. Any process that can read your environment can read it, so avoid it on your own machine |

## Why

1Password is great for developers: the `op` CLI, `op run`, `op://` secret references, Touch ID unlock, and the SSH agent make handling API tokens painless. But it's a paid subscription.

`stash` aims to give you that same developer workflow for free:

- **Free and open source.** No subscription, no account.
- **Your data stays on your machine.** One encrypted vault file. No cloud required.
- **Built for the terminal.** Every feature works from the CLI first.
- **Ready for AI agents.** A built-in MCP server lets tools like Claude Code use secrets without the secret values ending up in the model's context.

## Goals

**v1 goals**
- A fast CLI for storing and retrieving secrets
- Touch ID unlock on macOS, with the master password as a fallback
- Secret references (`stash://...`) you can put in `.env` and config files
- `stash run`, which injects secrets into one command's environment
- An MCP server for AI agents, with per-use approval and an audit log

**Non-goals for v1**
- Browser autofill
- Team or family sharing
- Cloud sync (planned for later, see Roadmap)
- Mobile apps

## Use secrets in your projects

### `stash run`: secrets for one command only

Put references instead of secret values in your `.env` file. It's safe to commit:

```sh
# .env
GITHUB_TOKEN=stash://github/token
OPENAI_API_KEY=stash://openai/api-key
PORT=3000
```

Then run your command through stash:

```sh
stash run --env-file .env -- npm start
```
```
✓ unlocked · injected 2 secrets into npm
> app@1.0.0 start · listening on :3000
```

- **What gets replaced:** any variable whose whole value is `stash://<name>` is swapped for the secret, only inside that one command. Your shell, your history, and your files never hold the secret.
- **Where references come from:** the current environment works too, for example `GITHUB_TOKEN=stash://github/token stash run -- gh repo list`. Values from `--env-file` take priority, and later files win.
- **Output masking:** if the command prints a secret, stash replaces it with `<concealed by stash>`. Use `--no-masking` to turn this off. Values shorter than 4 characters aren't masked.
- **Ctrl-C and exit codes:** both behave as if you ran the command directly.
- **No unlock without references:** if no references are found, stash runs the command without unlocking anything.

### `stash inject`: fill in config templates

```yaml
# config.tpl.yml (commit this)
database_url: {{ stash://db/url }}
api_key: {{ stash://openai/api-key }}
```

```sh
stash inject -i config.tpl.yml -o config.yml   # config.yml is created readable only by you
stash inject < config.tpl.yml                  # or print to stdout
```

If any reference is missing, nothing is written. Existing files are only overwritten with `--force`.

`stash get` also accepts a reference: `stash get stash://github/token`.

## AI and MCP integration

`stash mcp` runs an MCP server over stdio. Add it to Claude Code, Cursor, or any MCP client:

```json
{ "mcpServers": { "stash": { "command": "stash", "args": ["mcp"] } } }
```

| Tool | What the agent gets |
|---|---|
| `list_secrets` | Names and metadata only, never values |
| `run_with_secrets` | Runs a command with secrets injected as env vars. The agent sees the command's output, not the secrets |
| `request_secret` | The raw value, only after you approve that use with Touch ID. Off by default |

Safety rules:
- Secret values stay out of the model's context by default.
- Output from `run_with_secrets` is scanned, and any secret value that shows up in it is masked.
- Access can be limited per agent (for example, only `github/*`).
- Every agent access is written to an audit log (`stash audit`).

## Security model

- **Vault:** one SQLite file at `~/.stash/vault.db`. Each item is encrypted separately with XChaCha20-Poly1305. Secret names are encrypted too, so the file doesn't reveal which services you use.
- **Keys:** the master password goes through Argon2id to produce a key-encryption key. That key wraps a random 256-bit vault key, so changing the master password doesn't mean re-encrypting every item.
- **Touch ID:** the vault key is encrypted to a Secure Enclave key that only works after a fingerprint match (`biometryCurrentSet`). The Secure Enclave key never leaves the chip, and no Keychain entitlements or code signing are needed. If someone adds or removes a fingerprint, Touch ID unlock stops working until you run `stash touchid enable` again.
- **Sessions:** the agent keeps unlocked keys only in memory. It answers only processes running as your user, over a `0600` socket, and exits once it holds no keys.
- **Memory:** secrets are wiped from memory after use (`zeroize`) and never logged.
- **Threat model:** see [docs/threat-model.md](docs/threat-model.md), including what `stash` does *not* protect against, such as malware already running as your user.

## Architecture

```
stash (Rust workspace)
├── crates/stash-core      crypto, vault format, items
├── crates/stash-cli       the `stash` command, including the session agent (`stash agent`)
├── swift/stash-touchid    small Swift helper: Touch ID + Secure Enclave via CryptoKit
└── stash-mcp              MCP server (`stash mcp`), planned
```

Rust handles everything that is security-critical and cross-platform. The Swift helper is kept small and does only the macOS-specific Touch ID and Secure Enclave work. It talks to `stash` over pipes.

## Roadmap

| Version | Scope |
|---|---|
| v0.1 ✅ | Encrypted vault, CLI (`init`/`add`/`get`/`ls`/`rm`), master password |
| v0.2 ✅ | Touch ID unlock + agent sessions |
| v0.3 ✅ | `stash://` references, `run`, `inject` |
| v0.4 | MCP server with approvals and audit log |
| v0.5 | SSH agent, TOTP codes, git commit signing, `stash get --copy` with auto-clearing clipboard |
| Later | Encrypted sync (iCloud Drive or Git), menu bar app, browser extension, Linux support |

## How it compares

This compares stash's planned v1 with the other tools.

| | stash | 1Password | Bitwarden | pass / gopass |
|---|---|---|---|---|
| Price | Free | Paid | Free tier / paid | Free |
| Touch ID in CLI | ✅ | ✅ | Partial | ❌ |
| Secret references + `run` | ✅ | ✅ | Partial (Secrets Manager) | ❌ |
| MCP / AI-agent support | ✅ built in | Limited | ❌ | ❌ |
| Data stays local | ✅ | ❌ (cloud) | ❌ unless self-hosted | ✅ |
| Browser autofill | Later | ✅ | ✅ | Via plugins |

## Brand

The logo, colors, and type are documented in [docs/brand](docs/brand/README.md).

## Contributing

Contributions are welcome! Start with [CONTRIBUTING.md](CONTRIBUTING.md). In short: branch from `dev` and open pull requests against `dev`. `main` is the stable branch and only gets updated from `dev`.

Report security issues privately as described in [SECURITY.md](SECURITY.md). Please don't open public issues for them.

## License

[MIT](LICENSE)
