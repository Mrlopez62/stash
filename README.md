# stash

**A free, developer-first secrets manager for macOS. Unlock with Touch ID, pass API tokens into commands safely, and let AI agents use your secrets without ever seeing them.**

> Status: planning. Nothing here is built yet. This document describes the goal.

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

## What using it looks like

```sh
# Store and read secrets
stash add github/token              # prompts for the value (never put it in shell history)
stash get github/token              # Touch ID prompt, then prints the value
stash get github/token --copy       # copies it; the clipboard clears after 30s
stash ls                            # lists names only, never values

# Reference secrets instead of pasting them
cat .env
# GITHUB_TOKEN=stash://github/token
# OPENAI_API_KEY=stash://openai/api-key

# Inject secrets into one process only
stash run --env-file .env -- npm start

# Render a config file from a template
stash inject -i config.tpl.yml -o config.yml
```

After one Touch ID unlock, a background agent keeps the vault unlocked for a short session (10 minutes by default, configurable), so you aren't asked again for every command. This works like `ssh-agent`.

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

- **Vault:** one SQLite file at `~/.stash/vault.db`. Each item is encrypted separately with XChaCha20-Poly1305.
- **Keys:** the master password goes through Argon2id to produce a key-encryption key. That key wraps a random 256-bit vault key, so changing the master password doesn't mean re-encrypting every item.
- **Touch ID:** the vault key is kept in the macOS Keychain, guarded by a biometric access policy (`biometryCurrentSet`). If someone adds a new fingerprint, Touch ID unlock stops working until you enter the master password again.
- **Memory:** secrets are wiped from memory after use (`zeroize`) and never logged.
- **Threat model:** documented in `docs/threat-model.md` (to be written), including what `stash` does *not* protect against, such as malware already running as your user.

## Architecture

```
stash (Rust workspace)
├── stash-core      crypto, vault format, items
├── stash-cli       the `stash` command
├── stash-agent     background session holder (Unix socket, like ssh-agent)
├── stash-mcp       MCP server (`stash mcp`)
└── stash-touchid   small Swift helper for LocalAuthentication + Keychain
```

Rust handles everything that is security-critical and cross-platform. The Swift helper is kept small and does only the macOS-specific Touch ID and Keychain work.

## Roadmap

| Version | Scope |
|---|---|
| v0.1 | Encrypted vault, CLI (`add`/`get`/`ls`/`rm`), master password |
| v0.2 | Touch ID unlock + agent sessions |
| v0.3 | `stash://` references, `run`, `inject` |
| v0.4 | MCP server with approvals and audit log |
| v0.5 | SSH agent, TOTP codes, git commit signing |
| Later | Encrypted sync (iCloud Drive or Git), menu bar app, browser extension, Linux support |

## How it compares

| | stash | 1Password | Bitwarden | pass / gopass |
|---|---|---|---|---|
| Price | Free | Paid | Free tier / paid | Free |
| Touch ID in CLI | ✅ | ✅ | Partial | ❌ |
| Secret references + `run` | ✅ | ✅ | Partial (Secrets Manager) | ❌ |
| MCP / AI-agent support | ✅ built in | Limited | ❌ | ❌ |
| Data stays local | ✅ | ❌ (cloud) | ❌ unless self-hosted | ✅ |
| Browser autofill | Later | ✅ | ✅ | Via plugins |

## License

MIT
