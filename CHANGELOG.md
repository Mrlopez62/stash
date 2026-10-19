# Changelog

All notable changes to stash. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may change behavior).

## [0.12.0] - 2026-10-19

A security release, from an audit of how stash encrypts your data.

### Security
- **Vault format 3,** upgraded automatically on your next master-password unlock (or with `stash upgrade`), after copying the old file to `vault.db.v2-backup`:
  - **A separate key for cards, bank accounts, and SSH keys.** Their secret values are sealed under a *sensitive key* that sessions never hold; a redacted copy (cardholder, expiry, "Visa •••• 4242", SSH public keys) keeps lists working. Every use takes a fresh Touch ID or the master password, so the prompts for payment fills, SSH signatures, AI-agent requests, and `stash get cards/…` are now enforced by encryption, not just by policy.
  - **Tamper detection for the whole vault:** a MAC over every item and a write counter, checked on every open. Removing, adding, swapping, or rolling back items is now detected (before, only changes *within* an item were).
  - **New keys on upgrade**, and subkeys derived per purpose (item encryption, row ids, the vault MAC, key checks).
- **`stash passwd`** changes the master password and replaces both keys, re-encrypting every item, so an old copy of the vault with an old password opens nothing current. **`stash rekey`** replaces the keys without changing the password.
- **Stronger key derivation:** Argon2id now uses 256 MiB, 3 passes, 4 lanes (was 64 MiB, 1 lane); older vaults are re-wrapped on their next password unlock. Settings in the file are bounded before Argon2 runs, so an edited file can't make an unlock exhaust memory.
- **Touch ID carries both keys**; the helper denies debugger attach.
- **Card numbers and IBANs** are no longer copied into un-wiped memory while validating, summarizing, or normalizing.
- **`stash add --card`** asks for the cardholder, expiry, and ZIP when they aren't given as flags, keeping them out of shell history.
- **Clearer errors:** "wrong master password (or the vault's header was modified)", and a distinct error for a tampered vault.
- **Fixes from a second audit of format 3** (before release):
  - A process that unlocked before `stash passwd` or `rekey` could write with the old keys and leave the vault unopenable; every write now checks the keys still match ("unlock again") and `rekey` keeps a safety copy until the new vault verifies.
  - The vault-wide MAC is checked again under the write lock before every write, so a write can't sign over tampering done since the vault was opened; open-time checks run in one read transaction (no false "tampered" during concurrent writes).
  - The redacted copy of a card, bank account, or SSH key keeps values only from a fixed list of non-secret fields, whatever kind a client sends, and secret fields are always stored concealed (a crafted edit could otherwise have copied an SSH private key into it); the app server keeps a kept value's stored kind.
  - Unsplit card or SSH items are refused; upgrades through `stash mcp` and the SSH agent re-enroll Touch ID and end sessions too (or turn Touch ID off if they can't); backups use SQLite's `VACUUM INTO`, and a failed backup opens the old vault read-only instead of failing; `rekey` reads under the write lock; the sensitive key is dropped on every error path; the SSH agent no longer counts a password-from-the-environment unlock as approving a signature.
- **Fixes from a third audit** (also before release): a redacted copy relabeled as another kind is refused, and the app won't change a card's or SSH key's kind (either could have let an edit save hidden values under the main key); KDF strengthening, upgrades, and key replacement all run under the write lock with full checks (a concurrent rekey or a second upgrading process could otherwise lose data); the rekey safety copy is taken under the lock and removed on every failure; sessions and Touch ID follow new keys even if the post-rekey check fails.
- **The threat model** describes format 3, and corrects two claims: deleted items can survive in journals, snapshots, and backups (still encrypted), and the audit log records item names in plain text.

### Changed
- In the Mac app, revealing or editing a card, bank account, or SSH key asks for Touch ID each time. The app keeps only the main key.

## [0.11.0] - 2026-10-19

### Added
- **stash in sign-in fields (opt-in):** with *Show stash in sign-in fields* on in the extension's Settings, a stash icon appears in username and password fields. Clicking it opens the stash menu right there: logins for the site, cards, and bank accounts, with the same rules as the toolbar popup.
- **Saving logins:** after you sign in or sign up, stash offers to save the login; after a password change, to update it. Updates keep the old password in the item as `previous password`. A login is only ever saved for the page's own site, over https.
- **Native host requests** `check_saved` (never returns a value) and `save_login` (unlocks with a prompt naming the site if needed); saves are logged in the audit log.

### Security
- The feature is **off by default**: turning it on is what grants the extension access to sites, and turning it off removes it. With it off, nothing runs on any page.
- The menu and the save prompt are **extension pages in frames**, inside a closed shadow root: the page can't read your logins in them or click them for you. The icon only opens for a real click.

## [0.10.0] - 2026-10-18

### Added
- **Browser autofill** for Chrome, Brave, Edge, Arc, and Firefox: the stash extension's toolbar popup (⌘⇧L) lists the logins saved for the page, plus your cards and bank accounts, and fills the one you pick.
  - **Logins** fill only on their own site, matched by registrable domain (`github.com.evil.io` never matches `github.com`), on https pages or `localhost`. A 2FA step gets the current code.
  - **Cards and bank accounts** fill on any https page, with Touch ID every time, on a prompt naming the card and the site. Cards also fill Stripe and Braintree card frames inside the approved page.
  - **Fields are found** by the HTML `autocomplete` standard, then by names and labels; hidden fields are never filled.
- **`stash browser install | uninstall | status`:** connects your browsers to the vault and unpacks the extension to `~/.stash/browser-extension/chrome` (Chrome, Brave, Edge, Arc) and `.../firefox`, each with a manifest for that browser so neither shows warnings about the other's settings.
- **`stash native-host`:** the extension's bridge to the vault.
  - It serves only an allowed browser (a valid signature from a listed maker *and* a listed app identifier, so Chrome for Testing and other automation builds are refused), started directly or by one of that browser's own signed helpers, and only stash's extension IDs.
  - It refuses everything if the unpacked extension's files were changed.
  - It re-checks the site on every fill, pauses payment fills for 10 seconds after a declined prompt, and logs every fill in the audit log.
- **The extension** asks each frame whether it may be filled before sending any value, fills card frames only when they sit directly in the approved page, and fills nothing if the page changed while Touch ID was up.

## [0.9.1] - 2026-10-18

A security release, from a review of what a program running as you (an AI agent's shell, a malicious package script) could do.

### Security
- **The vault key goes only to the real session agent.** `stash` used to hand it to whatever listened on `~/.stash/agent.sock`; now it checks, through the kernel, that the listener runs the same `stash` executable, and warns if something else is there.
- **The Touch ID helper can't be swapped.** Release builds no longer look for `stash-touchid` on `$PATH` or in `$STASH_TOUCHID_HELPER` (now honored only in debug builds for tests), and the helper refuses every caller except the `stash` installed next to it.
- **`stash app-server` serves only the stash app it ships inside**, and the Mac app runs only its bundled backend (no `$STASH_BIN` or `$PATH` in release builds).
- **`stash mcp --no-approval` now requires `STASH_PASSWORD`**, so an agent that edits its own MCP config can't turn approvals off.
- **Prompts tell the truth about who's asking.** MCP prompts add the real process chain behind the server and any risky options (`--allow-reveal on`), say how long a command may run, and strip invisible Unicode formatting (bidirectional overrides, zero-width characters) that could disguise a command. Process names are cleaned the same way everywhere.
- **No debugger attach or core dumps** for any `stash` process.
- **The threat model has a new section** on programs running as you, including what's still possible (reading a running command's environment, the clipboard) and how to limit it.

## [0.9.0] - 2026-10-17

### Added
- **SSH keys in the vault:** `stash ssh generate` makes an Ed25519 key, and `stash ssh import` moves in an existing OpenSSH key file (passphrase-protected keys too). `stash ssh public` prints the public key; `stash ssh ls` lists keys with fingerprints.
- **The stash SSH agent** (`stash ssh agent`, or `stash ssh install` to run it at login with launchd):
  - Every signature asks for Touch ID, on a prompt naming the key, its purpose (an SSH login as a user, or a git commit signature), and the process asking.
  - Public keys stay listed while the vault is locked, so `ssh` picks a key without a prompt.
  - When the vault is locked, the unlock prompt names the signature it approves; an unlock for anything else never counts as approval.
  - Text from the requesting program (user names, namespaces) appears in the prompt only if short and plain.
  - After a declined prompt, signing is refused for 10 seconds, so a process can't keep asking.
  - Keys added while the agent runs are offered right away.
  - Requests to add, remove, or lock keys are refused.
  - Each signature is written to the audit log.
- **Git commit signing:** `stash ssh git-setup <key> [--global]` configures git to sign commits and tags through the agent, and records your key in an allowed-signers file so `git log --show-signature` verifies them.
- **In the Mac app:** an SSH Keys category; a key panel with its fingerprint, `ssh-keygen`-style randomart, and Copy Public Key; generating and importing keys from New Item. Copying an SSH key from the list copies its public key.

### Changed
- **`stash mcp` refuses SSH keys** (they're not listed, and references to them are blocked), since commands that need them get them through the agent.
- **`stash ls --long`'s third column is now DETAILS:** a login's username, or a card's, bank account's, or SSH key's summary, sized to fit.
- **Snapshot mode exits directly** instead of hanging when an editor sheet is open.

## [0.8.0] - 2026-10-17

### Added
- **Payment cards:** cardholder, number, expiry, security code, PIN, and billing ZIP.
  - **Validation:** the number must pass the Luhn checksum and match the brand's length (Visa, Mastercard, Amex, Discover, JCB, Diners, UnionPay are detected), expiry must be MM/YY, and the security code must be 3–4 digits.
  - **Display:** lists show "Visa •••• 4242 · 08/27". The app shows a 3D card:
    - It tilts toward the pointer under a moving highlight, and a foil sheen crosses it when it opens.
    - Clicking it turns it over to the security code, which is fetched only then. It turns back by itself after 30 seconds.
    - The editor shows a live card that fills in as you type and turns over while you enter the security code.
    - With Reduce Motion on, there's no tilt or sheen, and flips become fades.
- **Bank accounts:** bank, holder, type, routing number (ABA checksum), account number, IBAN (mod-97), SWIFT/BIC, and PIN.
- **Payment items in the CLI:** `stash add --card` and `--bank`. Numbers come only from hidden prompts (or one per line from stdin). New field aliases: `#cvv`, `#cvc`, `#expiry`, `#name`, `#zip`, `#routing`, `#account`.
- **`stash mcp --allow-payments`:** without it, AI agents can't list or use payment items.
- **Design doc for browser autofill** of logins and payments ([docs/design/autofill.md](docs/design/autofill.md)).

### Changed
- **Every save normalizes and validates payment fields** (card numbers, expiry, routing numbers, IBANs) in the core, so edits from the CLI, the app, and future clients are held to the same rules.

## [0.7.1] - 2026-10-17

### Changed
- **A redesigned Mac app.** It was rebuilt in the style of 1Password's app and reviewed twice by an independent UI-design agent.
  - **Layout:** a sidebar with sections and counts (kinds, two-factor, and folders), a page title with one primary action, and a card holding a dense item table.
  - **Table:** columns adapt to the window width and always leave room for names. Copy buttons appear on hover.
  - **Inspector:** the selected item opens in a panel beside the table.
  - **Editor:** rebuilt from the app's own components.
- **No "Two-Factor" sidebar filter.** It duplicated the table's 2FA column. The 2FA field and codes are unchanged.
- **Brand look throughout.** The app follows the system light or dark appearance, in the brand palette. It bundles JetBrains Mono and IBM Plex Sans (OFL), and keeps amber for the primary action, the selection, secrets, and 2FA timers.
- **Quick Access.** Keycap hints, ⌥↩ to copy a 2FA code, and a no-results state.

### Added
- **Scan 2FA QR codes** in the editor's Two-factor field.
  - Read the code from the screen (stash's own windows are left out of the capture), paste a screenshot, choose an image, or drop one onto the field.
  - Decoding is local, with Vision, and captures stay in memory.
  - New logins get their name and username filled in from the code.

- **Authenticator QR codes.** The QR button on a login's one-time password shows a code that phone authenticator apps can scan, built from the stored secret (setup keys work too). It's never shown as text, and it closes itself after 60 seconds.

### Fixed
- **Password generator** text was unreadable in light mode.
- **Cut-off window.** The window could be resized smaller than its content, which clipped the sidebar and inspector. It now has a real minimum size. At medium widths the sidebar tucks away while an item is open, and at the narrowest the inspector floats over the table.

## [0.7.0] - 2026-10-17

### Added
- **The stash Mac app (`stash.app`)** has a vault browser with search, item details with reveal and copy, live 2FA codes, an editor, and the password generator. It also adds a menu bar icon, Quick Access from anywhere with **⇧⌘Space**, and settings. It's built with `./scripts/build-app.sh` and needs only the Xcode Command Line Tools.
- **`stash app-server`** is the app's private backend: JSON-RPC over stdio, with values sent only on demand and an idle auto-lock.
- **Concealed clipboard.** Copies from the app are marked concealed and transient, kept off Universal Clipboard, and cleared after 30 seconds.

## [0.6.1] - 2026-10-17

Security and correctness fixes for 0.6.0, found by an independent security review. **Upgrade if you use 0.6.0.**

### Fixed
- **Older vaults.** A vault created before 0.6, unlocked with Touch ID or a session, accepted logins and notes. Older versions of stash then misread those items, and for items of 64 KiB or more could print their contents as a name. stash now refuses to store logins and notes until the vault has been unlocked once with the master password, and says so before asking for anything.
- **Lost notes and fields.** Notes or extra fields on a single-value secret were silently dropped. So were notes when you changed a secret's value. Both are now kept.
- **`--set` and secrets.** `--set` could put passwords and 2FA secrets on the command line, where shell history and `ps` can see them, and turn them into visible fields. It now refuses password, 2FA, and notes fields and common secret-sounding labels, and it keeps an existing field's type.
- **`--set` on a secret.** It no longer turns the secret into a login.
- **Empty values.** `--unset` could remove a secret's value, and empty piped input was saved as an empty secret. Both are refused.
- **2FA items from 0.5.** Short 2FA secrets saved by 0.5 stopped working. The 80-bit minimum now applies only to newly entered secrets.
- **MCP 2FA codes.** `stash mcp` generated 2FA codes before your approval, so they could expire while you approved. Values are now produced after approval, and a slow approval no longer asks twice.
- **Vault upgrade errors.** The upgrade to format 2 tolerates only a read-only or busy vault file (with a 5-second wait for other stash processes), and says clearly when that blocked it. Any other failure is reported.
- **Wiping secrets.** Old values are wiped from memory when replaced, revealed `show` output is wiped, and listing names no longer decrypts item contents.
- **Creation times.** `add --force` no longer keeps the replaced item's creation time.

### Changed
- **Docs.** The docs no longer overstate protection. An item's encrypted size can hint at its kind, MCP allowlists work per item, and generated symbols may need quoting in shells.

## [0.6.0] - 2026-10-17

### Added
- **New item kinds:** logins (username, password, website, 2FA, notes) and secure notes, alongside single-value secrets.
- **Field references:** `stash://github#username`, and `stash://github#otp` for the current 2FA code, in `get`, `run`, `inject`, and MCP.
- **Item commands:** `add --login` / `add --note`, `edit`, `show [--reveal]`, `ls --long`, and `generate` (password generator).

### Changed
- **Vault format 2.** Logins and notes use a new encrypted encoding, and older vaults upgrade when unlocked with the master password.

## [0.5.0] - 2026-10-17

### Added
- **`stash get --copy`:** copies to the clipboard, which is cleared after 30 seconds if it still holds the secret.
- **`stash otp`:** time-based 2FA codes (RFC 6238).

## [0.4.0] - 2026-10-17

### Added
- **`stash mcp`:** an MCP server for AI agents (`list_secrets`, `run_with_secrets`, and an opt-in `request_secret`), with a Touch ID approval for every use, `--allow` patterns, and an audit log (`stash audit`).

### Security
- **Scoped sessions.** Sessions now belong to the process that unlocked them. Commands started by `stash run`, scripts, and AI agents' shells must unlock for themselves, and the prompt says who's asking.

## [0.3.0] - 2026-10-17

### Added
- **References and injection:** `stash://` references, `stash run` (secrets for one command, with output masking), and `stash inject` (templates).

## [0.2.0] - 2026-10-17

### Added
- **Touch ID and sessions:** Touch ID unlock through the Secure Enclave, and unlocked sessions held by a background agent.

## [0.1.0] - 2026-10-17

### Added
- **The first release:** an encrypted vault (Argon2id + XChaCha20-Poly1305) and the `init`, `add`, `get`, `ls`, and `rm` commands.

[0.12.0]: https://github.com/Mrlopez62/stash/pull/16
[0.11.0]: https://github.com/Mrlopez62/stash/pull/16
[0.10.0]: https://github.com/Mrlopez62/stash/pull/15
[0.9.1]: https://github.com/Mrlopez62/stash/pull/14
[0.9.0]: https://github.com/Mrlopez62/stash/pull/13
[0.8.0]: https://github.com/Mrlopez62/stash/pull/12
[0.7.1]: https://github.com/Mrlopez62/stash/pull/11
[0.7.0]: https://github.com/Mrlopez62/stash/pull/10
[0.6.1]: https://github.com/Mrlopez62/stash/pull/9
[0.6.0]: https://github.com/Mrlopez62/stash/pull/8
[0.5.0]: https://github.com/Mrlopez62/stash/pull/7
[0.4.0]: https://github.com/Mrlopez62/stash/pull/6
[0.3.0]: https://github.com/Mrlopez62/stash/pull/5
[0.2.0]: https://github.com/Mrlopez62/stash/pull/4
[0.1.0]: https://github.com/Mrlopez62/stash/pull/1
