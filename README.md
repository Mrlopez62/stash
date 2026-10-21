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

A free, open-source password and secrets manager for macOS, built for developers. Unlock with Touch ID, fill passwords and cards in your browser, sign git commits with keys that never touch disk, pass API tokens into commands safely, and let AI agents use your secrets without ever seeing them.

> **Status: early development (v0.15).** Everything below works today:
> - **The stash Mac app:** menu bar, Quick Access (⇧⌘Space), vault browser and editor
> - **Items:** logins with 2FA codes, secrets, notes, **payment cards and bank accounts**, **SSH keys**
> - **Browser autofill** in Chrome, Brave, Edge, Arc, and Firefox, with saving new logins and cards
> - **Developer tools:** `stash://` references, `stash run`, `stash inject`, an SSH agent with git commit signing
> - **AI agents:** an MCP server with Touch ID approval for every use, and an encrypted audit log
>
> stash hasn't had an outside security review yet, so don't trust it with production secrets.

## The Mac app

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/vault-dark.png">
    <img src="docs/screenshots/vault.png" alt="The stash vault: sidebar with categories and folders, a table of items, and an inspector showing a GitHub login with a live 2FA code" width="820">
  </picture>
</p>
<p align="center"><img src="docs/screenshots/quick-access.png" alt="Quick Access search panel" width="560"></p>
<p align="center"><img src="docs/screenshots/card.png" alt="A payment card in stash, shown as a card face with only the last four digits" width="820"></p>

```sh
git clone https://github.com/Mrlopez62/stash.git && cd stash
./scripts/build-app.sh --install     # builds stash.app into ~/Applications
open ~/Applications/stash.app
```

- **Vault browser.** Search logins, secrets, notes, cards, bank accounts, and SSH keys, with copy buttons for every field and live 2FA codes with a countdown. Cards get a card face showing only the last four digits.
- **Quick Access** with **⇧⌘Space** from anywhere. Type a few letters, press Return, and the password is on your clipboard.
- **Menu bar icon.** Quick Access, lock and unlock, open stash.
- **Set up 2FA from the QR code.** In a login's Two-factor field, choose **Scan QR**: stash reads the code straight off your screen, even from a window behind stash. You can also paste or drop a screenshot. It fills in the item's name and username from the code.
- **Add a login's 2FA to your phone.** The QR button on the one-time password shows a code that Google Authenticator, Authy, or the iOS Passwords app can scan. It never shows the secret as text, and it closes itself after a minute.
- **Touch ID unlock** and a built-in **password generator**. The app locks itself after 10 idle minutes.
- **Safer copies.** They're marked concealed, so clipboard-history apps skip them. They stay on this Mac (no Universal Clipboard) and are cleared after 30 seconds.
- **The same vault as the CLI.** Everything you add in the app works with `stash run`, `stash inject`, and the MCP server, and the other way round.

Building needs Rust and the free Xcode Command Line Tools (`xcode-select --install`), not Xcode. The app is ad-hoc signed. If you build it yourself, macOS opens it normally.

## Getting started

Requires [Rust](https://rustup.rs) 1.88 or newer. On macOS, the Touch ID helper also needs Xcode or the Command Line Tools (`xcode-select --install`).

```sh
git clone https://github.com/Mrlopez62/stash.git
cd stash
./scripts/install.sh                  # installs `stash` (and `stash-touchid` on macOS)

stash init                            # create a vault (asks for a new master password)
stash touchid enable                  # macOS: unlock with your fingerprint from now on
stash add github/token                # prompts for the value without echoing it
stash add github --login --username octocat --url https://github.com --generate
echo "$OPENAI_KEY" | stash add openai/api-key   # or pipe it in
stash ls                              # names only
stash get github/token                # prints the value
stash get github/token --copy         # copies it instead; cleared after 30s
stash otp github/2fa                  # current 2FA code (from an otpauth:// URI or base32 secret)
stash rm github/token
stash lock                            # end the unlocked session now
```

How unlocking works:
- **The first command unlocks the vault.** With Touch ID turned on, that's a fingerprint prompt. Otherwise you type the master password. If Touch ID is cancelled or unavailable (for example, the lid is closed), stash asks for the master password instead.
- **Then a session starts, for that terminal only.** stash commands you run from the same shell in the next **10 minutes** don't ask again, and each use restarts the 10-minute timer. A small background agent holds the session, like `ssh-agent`. Run `stash lock` to end it early.
- **Everything else has to ask.** That includes commands started by `stash run`, scripts, other terminals, and AI agents. They all get their own Touch ID prompt, which says what they want and who is asking, for example: *stash-touchid is trying to unlock stash for “get stripe/secret”, requested by sh ← stash*.
- **Sessions pause while an AI agent runs.** An AI coding agent that's allowed to script your terminal app could type `stash` commands into your unlocked shell. So while one is running (Claude Code, Codex, Gemini CLI, Cursor's agent, Aider, and others), every command asks for Touch ID again, and the prompt says why. `stash agents` shows what's running. If you'd rather keep sessions, `stash agents --allow-sessions` turns this off after a Touch ID check (`--pause-sessions` turns it back on).

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
- **A full password manager, too.** A native Mac app, browser autofill, cards and bank accounts, and an SSH agent, all from the same vault.
- **Ready for AI agents.** A built-in MCP server lets tools like Claude Code use secrets without the secret values ending up in the model's context.

## Not planned yet

- Team or family sharing
- Mobile apps
- Cloud sync (planned for later as encrypted sync through iCloud Drive or Git; see the Roadmap)

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
- **New `.env` files ask first:** a `.env` file in a repository you cloned was written by someone else, and it chooses which of your secrets the command gets. So the first time a file asks for secrets, and whenever the secrets it asks for change, stash asks for Touch ID (or your master password) naming the file and the secrets, even in an unlocked session. Changing plain values like `PORT` doesn't ask again. Approve ahead of time with `stash trust .env`, and withdraw with `stash trust --remove .env` (or `stash trust --reset` for all). Templates for `stash inject -i` work the same way. With `STASH_PASSWORD` set (scripts and CI), files aren't asked about.

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

### Payment cards and bank accounts

```sh
stash add cards/visa --card --cardholder "Samus Aran" --expiry 08/27   # asks for the number and security code
stash add banks/chase --bank --bank-name Chase --routing 021000021 --account-type checking
stash get cards/visa            # the card number
stash get cards/visa#cvv        # also #expiry, #name, #zip
stash ls --long                 # "Visa •••• 4242 · 08/27"
```

- **Typos are caught before they're saved.** Card numbers must pass their Luhn checksum and match the brand's length, and expiry must be a real MM/YY. Routing numbers are checked with the ABA checksum and IBANs with mod-97.
- **Last four only in lists.** `show`, `ls --long`, and the app show just the last four digits until you reveal. In the app, a card gets a card face.
- **Off-limits to AI agents by default.** `stash mcp` won't list or use cards and bank accounts unless you start it with `--allow-payments`. Blocked attempts go in the audit log.

### SSH keys and git commit signing

Keep SSH keys in the vault instead of `~/.ssh`. The stash SSH agent hands them to `ssh` and `git`, and every signature asks for Touch ID.

```sh
stash ssh generate ssh/github            # a new Ed25519 key; prints the public key for GitHub
stash ssh import ssh/work ~/.ssh/id_ed25519   # or move an existing key in (asks for its passphrase)
stash ssh install                        # run the agent at login, and print the ~/.ssh/config line
stash ssh git-setup ssh/github --global  # sign every commit and tag with it
```

Then add the `IdentityAgent` line that `install` prints to the top of `~/.ssh/config`, and `ssh`, `git push`, and `git commit` use your stash keys.

- **Touch ID per signature,** on a prompt that names the key, what it's for ("log in as git", "sign a git commit"), and the process asking.
- **Private keys never leave stash.** Not to disk, not to AI agents: `stash mcp` refuses SSH keys outright, since commands that need them get them through the agent.
- **Ed25519 keys,** in OpenSSH's format. Keys made by stash work with `ssh-keygen`, and `ssh-keygen` keys (including passphrase-protected ones) import into stash.
- **Every signature is logged** in the audit log (`stash audit`), by key name.

### Browser autofill

Fill sign-in forms and checkout pages from the vault, in Chrome, Brave, Edge, Arc, and Firefox.

```sh
stash browser install     # connects your browsers, then shows how to load the extension
```

Click the stash icon in the toolbar (or press ⌘⇧L) on a page: you'll see the logins saved for that site, plus your cards and bank accounts. Pick one and stash fills it in.

- **Logins only fill on their own site.** `github.com.evil.io` never gets your GitHub password; it isn't even suggested. Pages must be https (except `localhost`).
- **Every card or bank fill asks for Touch ID,** on a prompt that names the card and the site.
- **Nothing fills by itself.** Only your click in the stash popup fills a page, and the extension can only touch the tab you clicked it on. Hidden fields are never filled.
- **2FA codes too:** on a sign-in page's 2FA step, the same pick fills the current code.
- **No secrets in the browser.** The extension holds no data; it asks the vault for one item at a time, right before filling.

**Optional: stash in sign-in fields, and saving logins.** In the extension's Settings, turn on *Show stash in sign-in fields*. A stash icon then appears in username and password fields, and after you sign in or sign up, stash offers to save the login (or to update a password you changed, keeping the old one in the item). At checkout, it offers to save a new card (with Touch ID). It's off by default because it needs access to the sites you visit; with it off, stash only touches the tab whose toolbar button you click.

### Logins, notes, and passwords

Items come in three kinds: a single **secret** (an API token), a **login** (username, password, website, optional 2FA), or a **note**.

```sh
stash add github --login --username octocat --url https://github.com --generate
stash add github --login --otp           # type the password, then paste the 2FA secret
stash add notes/wifi --note

stash show github                        # fields, with passwords and codes hidden
stash show github --reveal
stash ls --long                          # kind, username, website, 2FA for every item

stash edit github --generate             # new random password
stash edit github --otp                  # add or replace 2FA
stash edit github --set recovery-email=me@example.com --unset website

stash generate --length 32 --no-symbols  # just a password
```

**Reference one field with `#`:**
- `stash://github` is a login's password, so existing references keep working.
- `stash://github#username` is its username.
- `stash://github#otp` is the **current 2FA code**.

These work everywhere references do: `stash get github#username`, `.env` files for `stash run`, `stash inject` templates, and the MCP server.

Passwords, 2FA secrets, and notes are only ever read from a hidden prompt or stdin, never from flags, so they stay out of your shell history.
- **`--set` is for visible fields only.** It refuses password, 2FA, and notes fields, plus common secret-sounding labels like `token`, `api key`, `client secret`, and `pin`. That label check is a safety net, not a guarantee: never put a secret value on the command line. Store it as its own item and reference it.
- **`--set` on a secret keeps it a secret.** An API key with a `scope` field is still an API key. Only `--username`, `--url`, and `--otp` turn an item into a login.
- **The note prompt reads one line.** Pipe multi-line notes in instead: `stash add notes/x --note < notes.txt`.
- **Generated passwords** use the OS random number generator with uniform sampling and always include each enabled character type. Symbols like `$` and `#` mean something in shells and some `.env` parsers, so quote them, or use `--no-symbols`.
- **Older vaults need one upgrade.** A vault made before v0.6 can store logins and notes once you've unlocked it with your master password once. Until then, stash asks you to.

### Clipboard and 2FA codes

- **`stash get <name> --copy`** puts a secret on the clipboard instead of printing it.
  - On macOS, it's marked concealed so clipboard-history apps skip it, and it stays on this Mac (no Universal Clipboard), just like copies from the app.
  - It's cleared after 30 seconds, but only if the clipboard still holds that secret, so something you've copied since is left alone.
  - `STASH_CLIPBOARD_TIMEOUT` changes the delay, and `0` keeps the value.
- **`stash otp <name>`** prints the current 2FA code, from a 2FA secret or a login's 2FA field. Add `--copy` to copy it instead.
  - **Adding a 2FA item:** store either the `otpauth://totp/...` URI from the 2FA setup QR code or the base32 secret shown under "can't scan it?", with `stash add github/2fa`.
  - **Code formats:** 6–8 digits, any period, and SHA-1, SHA-256, or SHA-512, checked against the RFC 6238 test vectors.

## AI and MCP integration

`stash mcp` is an MCP server that lets AI agents like Claude Code and Cursor *use* your secrets without ever *seeing* them.

```sh
# Claude Code
claude mcp add stash -- stash mcp --allow 'github/*' --allow 'openai/*'
```

```json
// Other MCP clients
{ "mcpServers": { "stash": { "command": "stash", "args": ["mcp", "--allow", "github/*"] } } }
```

| Tool | What the agent gets |
|---|---|
| `list_secrets` | Names of the secrets it's allowed to use. Never values |
| `run_with_secrets` | Runs a command with `stash://` env vars filled in, and gets back the exit code and output, with secret values replaced by `<concealed by stash>` |
| `request_secret` | A raw value. Only offered with `--allow-reveal` |

**You approve every use with your fingerprint.** Each `run_with_secrets` call (and each reveal) shows a Touch ID prompt naming the exact command and secrets, for example: *stash-touchid is trying to let claude-code run \`npm test\` with github/token*. The agent can't answer or fake that dialog. Cancel it, and the command never runs.

| Option | What it does |
|---|---|
| `--allow <pattern>` | Only let agents touch matching items (`*` matches anything, repeatable). Anything else is refused before any prompt. An allowed login's fields are all reachable (`#username`, `#notes`, `#otp`), so keep anything an agent shouldn't see in a separate item |
| `--allow-reveal` | Offer `request_secret`. Off by default; prefer `run_with_secrets` |
| `--allow-payments` | Let agents use payment cards and bank accounts. Off by default; most agents never need them |
| `--no-approval` | Skip the Touch ID approvals. Only for headless setups that use `STASH_PASSWORD` |

More safeguards:
- **No shell session.** The MCP server never creates or reuses one, so the agent's own shell commands can't read your vault either. It keeps the key in its own memory and forgets it after 10 idle minutes.
- **A clean environment for commands.** Commands get no stdin, and they're killed after a timeout (120 s by default, 900 s at most).
- **Nothing keeps running with your secrets.** When a command ends, stash stops anything it left running, even processes it detached with `nohup` or `setsid`, and says so in the result.
- **An encrypted audit log.** Every request (who, what, which secret names, approved/denied/blocked, exit code) goes to `~/.stash/audit.log`. It never holds values, and each entry is encrypted to the vault, so the names of your secrets and sites aren't readable without unlocking. View it with `stash audit` (`--json` for one JSON object per line).

## Security model

- **Vault:** one SQLite file at `~/.stash/vault.db`. Each item is encrypted separately with XChaCha20-Poly1305. Secret names are encrypted too, so the file doesn't reveal which services you use. A MAC over the whole vault detects items being removed, added, or rolled back.
- **Keys:** the master password goes through Argon2id (256 MiB) to produce a key-encryption key. That wraps two random 256-bit keys: the *main key* for everyday items, and a *sensitive key* that alone can read card numbers, CVVs, PINs, bank account numbers, and SSH private keys. Sessions only ever hold the main key, so those always need a fresh Touch ID or the master password.
- **Changing keys:** `stash passwd` changes the master password and replaces both keys (re-encrypting everything), so an old copy of the vault with an old password opens nothing current. `stash rekey` replaces the keys alone.
- **Touch ID:** the vault's keys are encrypted to a Secure Enclave key that only works after a fingerprint match (`biometryCurrentSet`). The Secure Enclave key never leaves the chip, and no Keychain entitlements or code signing are needed. If someone adds or removes a fingerprint, Touch ID unlock stops working until you run `stash touchid enable` again.
- **Sessions:** the agent keeps the main key only in memory, and only hands it to the real stash agent. It answers only processes running as your user, over a `0600` socket, and exits once it holds no keys.
- **Memory:** secrets are wiped from memory after use (`zeroize`) and never logged.
- **Audit log:** requests from AI agents, the browser, and SSH clients are logged by name, never by value, and each entry is encrypted so only an unlocked vault can read it.
- **Files from other people:** a `.env` file or template that asks for secrets needs your approval the first time, so a cloned repository can't choose which of your secrets it gets.
- **Threat model:** see [docs/threat-model.md](docs/threat-model.md), including what `stash` does *not* protect against, such as malware already running as your user.

## Architecture

```
stash
├── crates/stash-core      crypto, vault format, items, site matching
├── crates/stash-cli       the `stash` command: CLI, session agent, MCP server,
│                          SSH agent, browser bridge (native host), app backend
├── swift/stash-touchid    small Swift helper: Touch ID + Secure Enclave via CryptoKit
├── macos/StashApp         the Mac app (SwiftUI); UI only, it talks to `stash app-server`
└── browser/extension      the browser extension (Chrome, Brave, Edge, Arc, Firefox)
```

Rust handles everything that is security-critical: the vault, keys, and every decision about who gets what. The Swift helper only does the macOS-specific Touch ID and Secure Enclave work, and the Mac app and browser extension never hold the vault key. They all talk to `stash` over pipes.

## Roadmap

| Version | Scope |
|---|---|
| v0.1 ✅ | Encrypted vault, CLI (`init`/`add`/`get`/`ls`/`rm`), master password |
| v0.2 ✅ | Touch ID unlock + agent sessions |
| v0.3 ✅ | `stash://` references, `run`, `inject` |
| v0.4 ✅ | MCP server with Touch ID approvals, allowlists, and an audit log; sessions scoped to your shell |
| v0.5 ✅ | `stash get --copy` with a self-clearing clipboard, 2FA (TOTP) codes |
| v0.6 ✅ | 1Password-style items: logins with username, password, URL, 2FA, and notes; `#field` references; password generator |
| v0.7 ✅ | **The stash Mac app:** menu bar, Quick Access (⇧⌘Space), vault browser and editor, Touch ID, concealed clipboard. Ships the CLI and helpers inside `stash.app` |
| v0.7.1 ✅ | 1Password-style redesign, bundled brand fonts, 2FA QR scanning and authenticator QR export |
| v0.8 ✅ | **Payment cards** (card face, brand and checksum validation) and **bank accounts** (routing and IBAN validation), kept away from AI agents by default |
| v0.9 ✅ | **SSH keys:** an SSH agent with Touch ID per signature, git commit signing, Ed25519 generate and import |
| v0.10 ✅ | **Browser autofill** for logins, 2FA codes, cards, and bank accounts in Chrome, Brave, Edge, Arc, and Firefox, with Touch ID for every payment fill. See the [design](docs/design/autofill.md) |
| v0.11 ✅ | Autofill (opt-in): a stash icon in sign-in fields, and saving new logins and changed passwords |
| v0.12 ✅ | **Security:** vault format 3 (a separate key for cards, bank accounts, and SSH keys; tamper detection for the whole vault), `stash passwd` and `stash rekey`, stronger Argon2id |
| v0.13 ✅ | Saving new cards at checkout (opt-in, Touch ID to save) |
| v0.14 ✅ | Hardening: new or changed `.env` files and templates need a fresh approval (`stash trust`), an encrypted audit log |
| v0.15 ✅ | Hardening: sessions pause while AI agents run (`stash agents`), concealed CLI clipboard copies, MCP commands can't leave processes running with your secrets |
| v0.16 | Safari (needs a signed release) |
| v0.x | A configurable Quick Access shortcut, launch at login, a signed and notarized download |
| Later | Encrypted sync (iCloud Drive or Git), Linux support |

## How it compares

How stash compares today:

| | stash | 1Password | Bitwarden | pass / gopass |
|---|---|---|---|---|
| Price | Free | Paid | Free tier / paid | Free |
| Touch ID in CLI | ✅ | ✅ | Partial | ❌ |
| Secret references + `run` | ✅ | ✅ | Partial (Secrets Manager) | ❌ |
| MCP / AI-agent support | ✅ built in, with per-use Touch ID approval | Limited | ❌ | ❌ |
| Data stays local | ✅ | ❌ (cloud) | ❌ unless self-hosted | ✅ |
| SSH agent + git signing | ✅ with Touch ID per signature | ✅ | ❌ | ❌ |
| Browser autofill | ✅ with Touch ID per payment | ✅ | ✅ | Via plugins |

## Brand

The logo, colors, and type are documented in [docs/brand](docs/brand/README.md).

## Contributing

Contributions are welcome! Start with [CONTRIBUTING.md](docs/CONTRIBUTING.md). In short: branch from `dev` and open pull requests against `dev`. `main` is the stable branch and only gets updated from `dev`.

Report security issues privately as described in [SECURITY.md](docs/SECURITY.md). Please don't open public issues for them.

## License

[MIT](LICENSE)
