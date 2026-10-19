# Threat model

This document covers what stash protects against, how it does it, and what it doesn't protect against. It describes **v0.12**: an encrypted vault file (format 3), the CLI, Touch ID unlock, sessions scoped to your shell, `stash run` / `stash inject`, the MCP server for AI agents, the SSH agent, the Mac app, and browser autofill.

## What we protect

The names and values of the secrets in your vault, with the most protection for cards, bank accounts, and SSH keys.

## Vault format (version 3)

The vault is a single SQLite file, `~/.stash/vault.db` by default.

| Piece | How it's protected |
|---|---|
| Master password | Never stored. It goes through **Argon2id** (256 MiB, 3 passes, 4 lanes) with a random 16-byte salt to produce a key-encryption key (KEK). The settings are checked against fixed bounds *before* Argon2 runs, so an edited file can't make an unlock exhaust memory. Vaults with weaker settings are re-wrapped with these on their next master-password unlock. |
| Two vault keys | 32 random bytes each, from the operating system's random number generator, each wrapped with the KEK using **XChaCha20-Poly1305**, bound to which key it is, the format version, the KDF settings, and the salt. The **main key** reads every item's name and non-secret parts; sessions and Touch ID unlocks hold it. The **sensitive key** alone reads the secret values of cards, bank accounts, and SSH keys. |
| Subkeys | Derived from the main key with HMAC-SHA256 and distinct labels: one encrypts items, one makes row ids, one authenticates the vault, one checks that a key belongs to this vault. |
| Item names | Never stored in plaintext. Each row's id is `HMAC-SHA256(index key, name)`. The name is also encrypted along with the contents. |
| Item contents | Encrypted with XChaCha20-Poly1305, a fresh random 24-byte nonce each time, bound to the row id, so an encrypted item can't be moved to a different row. |
| Cards, bank accounts, SSH keys | Stored twice: a **redacted copy** under the item key, so lists and the app can show them, and the **full item** under the sensitive key. The redacted copy keeps values only from a fixed list of non-secret fields (cardholder, expiry, billing ZIP; bank, holder, account type, routing number, SWIFT; SSH public key and fingerprint); every other value is blanked, whatever kind a client labels it, and the secret fields are always stored as concealed. A redacted copy must be a card, bank account, or SSH key and match its sealed item's kind (stash refuses one relabeled as another kind), and the app won't change such an item into another kind. A session, or any program that gets the main key, can't decrypt a card number, CVV, PIN, account number, or private key. |
| The whole vault | **A vault-wide MAC** over every row (its id and the hashes of both encrypted parts) and a write counter. It's checked on every open (in one read transaction), and again at the start of every write, under the write lock, before the change and the new MAC are written in the same transaction. Removing, adding, swapping, or rolling back individual items makes stash refuse the vault, and a later write can't sign over the tampering. Every write also checks that this process's keys still match the file, so a process that unlocked before `stash passwd` or `rekey` gets "unlock again" instead of corrupting the vault. |
| Deleted items | SQLite's `secure_delete` overwrites freed pages in the vault file with zeros. Copies elsewhere aren't covered: SQLite's rollback journal, APFS snapshots, and backups can hold earlier versions of the file. They stay encrypted, under the keys and password of the moment they were made. |
| File permissions | The vault file is created with mode `0600`, and new parent directories with `0700`. |

**Upgrading from versions 1 and 2.** They open, read-only, with the master password, Touch ID, or a session. A master-password unlock (or `stash upgrade`) upgrades them: stash copies the old file to `vault.db.v2-backup` (mode `0600`), then in one transaction generates new keys, re-encrypts every item (splitting the sensitive kinds), writes the MAC, and strengthens the KDF settings. Touch ID is re-enrolled with the new keys and sessions holding the old key end.

**Replacing keys.** `stash passwd` (change the master password) and `stash rekey` both generate new main and sensitive keys and re-encrypt every item, so an old copy of the vault and an old (perhaps leaked) password open nothing current. Old copies remain readable with the password they were made with. During the change, stash keeps a safety copy (`vault.db.rekey-backup`, old keys) under the write lock and deletes it as soon as the new vault opens and decrypts; it stays only if that final check fails, and the error names it.

**Concurrency.** Upgrades, key replacement, and the automatic KDF strengthening each run under SQLite's write lock with the same checks as any write, so two stash processes can't both upgrade a vault, and a process that unlocked earlier can't put old keys back.

## Threats and how stash handles them

| Threat | Protected? | How |
|---|---|---|
| Someone copies your vault file (stolen laptop backup, synced folder, etc.) | ✅ | Without the master password they only have ciphertext. Argon2id at 256 MiB per guess makes guessing slow and expensive. |
| Someone without your keys edits the vault file: changes, swaps, removes, adds, or rolls back items, or tampers with the KDF settings | ✅ detected | Per-item authenticated encryption plus the vault-wide MAC, checked on open and before every write: stash refuses the vault. It **can't** stop someone deleting the whole file, or replacing it with an entire older copy of itself (which is self-consistent), so keep backups and protect them. |
| A program that has the main key editing the vault | Partial | The MAC key comes from the main key, so such a program can delete or roll back items (including a card's sealed part) and re-sign. It still can't *read* sensitive values, and stash refuses a card or SSH key that isn't split. |
| A program that gets the main key (from a session, or a running stash process) reading your cards or SSH keys | ✅ | Those values are sealed under the sensitive key, which no session holds. Every use needs a fresh Touch ID or the master password, and long-lived processes forget the key right after each use. |
| An old backup plus an old password | ✅ after `stash passwd` | Changing the password replaces the keys, so the old pair decrypts only that old copy. |
| Someone learns what services you use from the secret names | Partial | Names are encrypted. The number of items and their encrypted sizes are visible (sizes can hint at an item's kind), and the audit log (`audit.log`, mode `0600`) records item names and sites in plain text. |
| Other user accounts on the same Mac | ✅ | File permissions keep them out. |
| Secrets left lying around in memory | Partial | Keys, passwords, and values are wiped when they're no longer needed (`zeroize`), including card numbers during validation. But temporary copies made by the OS, the terminal, JSON parsing, or growing buffers can't all be guaranteed wiped. |
| Weak master password | Partial | stash requires at least 8 characters and Argon2id slows guessing down. A short password can still be cracked offline. Use a long passphrase. |

## Programs running as you (including AI agents)

The most likely attacker on a developer's Mac isn't a stranger: it's a program running *as you*. That includes an AI coding agent with a shell, possibly steered by prompt injection, or a malicious package script. stash can't stop such a program from running commands, but it makes sure the vault key never reaches it without a prompt that tells the truth about who's asking.

- **No key for impostors.** Before handing the vault key to the session agent, `stash` asks the kernel which program is listening on the socket and refuses unless it's the same `stash` executable. A look-alike listener on `~/.stash/agent.sock` gets nothing (`an_impostor_agent_never_gets_the_vault_key`).
- **The Touch ID helper can't be swapped.** Release builds use only the `stash-touchid` installed next to `stash`, never `$PATH` or `$STASH_TOUCHID_HELPER` (honored only in debug builds, for tests). The helper itself serves only the `stash` next to it, so no other program can show a stash Touch ID prompt or receive a key from it.
- **Backends serve only their owners.** `stash app-server`, which can read the whole vault once unlocked, refuses to run unless it was started by the stash app it ships inside. The Mac app runs only the backend sealed in its own bundle.
- **Prompts name the real requester.** Requester names come from the kernel, not from what a program says about itself. `stash mcp` prompts show both the client's self-chosen name and the process chain that started the server, plus risky options in effect (`--allow-reveal on`). Invisible Unicode formatting characters (bidirectional overrides, zero-width characters) are stripped from everything shown in a prompt, so a command can't be disguised.
- **`stash mcp --no-approval` needs `STASH_PASSWORD`.** Otherwise an agent that edits its own MCP configuration could turn off approvals.
- **No debuggers or core dumps.** Every `stash` process denies debugger attach (`PT_DENY_ATTACH` on macOS, `PR_SET_DUMPABLE=0` on Linux) and disables core dumps, so another program running as you can't read keys from its memory. One exception on Linux: the session agent stays dumpable, because that's what lets `stash` confirm it's really stash before handing it a key; there it relies on the kernel's Yama ptrace restrictions (on by default on Ubuntu and Fedora).

What stays possible for a program running as you, and how to limit it:

| Risk | Why | What to do |
|---|---|---|
| Reading the environment of a running `stash run` (or MCP `run_with_secrets`) command | macOS and Linux let any process of the same user read another's environment (`ps eww`). Secrets passed as environment variables are visible while that command runs. | MCP prompts say how long a command may run; approve short commands. Run AI agents in a sandbox that can't inspect other processes. |
| Reading the clipboard | Any app can read the clipboard while a copied secret is on it (up to 90 seconds). | Prefer `stash run` and `stash inject` while an AI agent is active. |
| Typing into your unlocked terminal | With macOS Automation permission for your terminal, a program can run commands inside it (`osascript … do script`), reusing that shell's session. | Don't grant Automation access to terminals to agents; `stash lock` (or `STASH_SESSION_TIMEOUT=0`) while agents run. |
| Replacing the `stash` binary or editing shell startup files | Files you can write, a program running as you can write. | Install `stash.app` in `/Applications` (admin-owned). Signed, notarized releases are planned. |
| Editing the audit log | It's a file you own. | Treat the log as a record, not proof. |

## What stash does *not* protect against

- **Malware running as your user,** beyond what the section above covers. It can read your keystrokes or simply run `stash get` and hope you approve the prompt. Read every prompt; decline anything you didn't cause. No local password manager can fully defend against this.
- **`STASH_PASSWORD`.** If you set this environment variable, any process that can read your environment can read your master password. It's meant only for scripts and CI.
- **Secrets after you use them.** Once `stash get` prints a value, stash can't control what your shell, terminal scrollback, or the receiving program does with it. The planned `stash run` reduces this exposure.
- **Losing your master password.** There's no recovery. Without the password, the vault can't be opened.

## Touch ID unlock (macOS)

`stash touchid enable` asks for the master password once. Then the `stash-touchid` helper:

1. creates a P-256 key **inside the Secure Enclave**, with the access control `privateKeyUsage + biometryCurrentSet`
2. encrypts the vault's two keys (main and sensitive) to that key: an ephemeral ECDH key exchange, HKDF-SHA256, and ChaCha20-Poly1305
3. saves the result as `<vault>.touchid` (mode `0600`). The file holds the encrypted keys and an encrypted handle to the Secure Enclave key, which is useless on any other Mac.

To unlock, the helper asks for a fingerprint and then has the Secure Enclave do the key exchange. The keys are passed back to `stash` over a pipe, never as a command-line argument. Before using them, `stash` checks each against the vault's check values, so a stale or swapped `.touchid` file is rejected. Every fingerprint recovers both keys, but only the main key ever goes to a session: whenever a card, bank account, or SSH key is used, it's from a fresh fingerprint. The helper refuses to attach debuggers.

| Threat | Protected? | How |
|---|---|---|
| Someone copies `vault.db` and `vault.db.touchid` to another machine | ✅ | The Secure Enclave key can't leave this Mac's chip, so the `.touchid` file is useless elsewhere. They're left with the master-password protection described above. |
| Someone with your unlocked Mac but not your finger | ✅ | The Secure Enclave won't use the key without a fingerprint match. |
| Someone enrolls their own fingerprint on your Mac | ✅ | `biometryCurrentSet` makes the key unusable after any fingerprint change. Run `stash touchid enable` again (with the master password). |
| Malware running as your user calling the helper directly | ✅ | The helper serves only the `stash` installed next to it (checked from the kernel's view of who started it). |
| Malware running as your user running `stash` itself | Partial | `stash` shows a prompt naming the process chain behind the request, so read what the dialog says. |

## Unlocked sessions (the agent)

After an unlock, `stash` starts `stash agent` in the background. The agent keeps the vault key in memory so one fingerprint covers several commands, but only for the process that unlocked.

- **Socket:** `~/.stash/agent.sock`, mode `0600`, inside the `0700` directory `~/.stash`.
- **Same-user check:** the agent checks every connection's user id (`getpeereid` / `SO_PEERCRED`) and ignores other users.
- **Sessions are scoped to the unlocking process's parent.** When `stash` hands the agent a key, the agent asks the kernel which process connected (`LOCAL_PEERPID` / `SO_PEERCRED`). It records that process's parent, usually your shell, by pid *and* start time. A later request gets the key only if the requester's parent is that same process. A recycled pid doesn't match, because its start time differs. Callers never state who they are: it all comes from the kernel.
- **Anyone else unlocks for themselves.** The prompt names the request and the process chain behind it, so an unexpected prompt is visible.
- **Timeout:** each key is forgotten after 10 minutes without use (`STASH_SESSION_TIMEOUT`). `stash lock` forgets all keys immediately. The agent exits once it holds no keys.
- **Memory only:** keys are never written to disk and are wiped from memory when dropped.
- **Only the main key.** Sessions never hold the sensitive key, so a program that reaches a session (see below) still can't read cards, bank accounts, or SSH private keys: those always prompt.
- **Only to the real agent:** `stash` hands a key only to a listener running the same `stash` executable, so a program listening on the socket path in its place never gets one.

| Threat | Protected? | How |
|---|---|---|
| Other user accounts | ✅ | Socket permissions plus the user id check on every connection. |
| A command launched by `stash run` reading other secrets | ✅ | It isn't a child of your shell, so it gets no session. Any `stash` call it makes triggers a prompt naming it (e.g. `sh ← stash`). Covered by the `run_children_cannot_ride_the_session` test. |
| Scripts, other terminals, and AI agents' shells | ✅ | Each has a different parent, so each must unlock with its own prompt. If you approve one, the new session belongs to that process. |
| Orphaned or daemonized processes | ✅ | Their parent becomes `launchd`/`init`, which never owns a session. |
| A program you start *directly from the unlocked shell* during a session | ❌ | Its parent *is* your shell, so it can reach the agent, just as with `ssh-agent` or 1Password's CLI. This applies to programs you type yourself, like `node script.js`, not to what those programs spawn. Run untrusted programs through `stash run`, use `stash lock`, or set `STASH_SESSION_TIMEOUT=0`. |
| A forgotten unlocked session | Partial | It ends by itself after 10 idle minutes, and `stash lock` ends it at once. |
| Malware that can inject code into your shell (ptrace and similar) | ❌ | It can act as your shell. On macOS this needs privileges that ordinary processes don't have. |

## `stash run` and `stash inject`

`stash run` puts secret values into one child process's environment. `stash inject` writes them into one output file.

- **No secrets on the command line.** References are resolved inside stash, and values reach the child only through its environment. They never appear in arguments, which other users can see with `ps`.
- **The master password stays behind.** `STASH_PASSWORD` is always removed from the child's environment.
- **Keys are wiped before the command starts.** stash drops the vault, and its keys, before the child starts.
- **Output files are private.** `stash inject` creates its output with mode `0600` and writes nothing if any reference fails to resolve.

| Threat | Protected? | How |
|---|---|---|
| Secrets in shell history, dotfiles, or committed `.env` files | ✅ | Files hold only `stash://` references. |
| The child echoing a secret into logs or a terminal recording | Partial | Output masking replaces exact matches of each secret (4 bytes or longer) in stdout and stderr. Encoded or transformed copies (base64, URL-encoding, split lines) aren't caught. Masking also makes the child's output a pipe rather than a terminal, so some tools turn off colors. `--no-masking` restores the terminal. |
| Other processes reading the child's environment | Partial | Other users can't. Processes running as *you* can read it (for example, with `ps eww` on some systems). That's inherent to environment variables. |
| The child itself misusing the secrets it was given | ❌ | You're choosing to give that program those secrets. It can't reach *other* secrets without a prompt (see sessions above). Only `stash run` programs you trust. |
| Rendered `stash inject` files left on disk | Partial | They're `0600`, but they hold plaintext. Prefer `stash run` where possible, and keep rendered files out of git. |

## Clipboard copy (`--copy`)

- **No secrets in arguments:** the value reaches `pbcopy` (or `wl-copy` / `xclip`) through a pipe, never as an argument.
- **Clearing is hash-based:** a detached `stash clipboard-clear` process gets only a SHA-256 hash of the value. After 30 seconds it clears the clipboard only if it still matches, so it never wipes something you copied since.

| Threat | Protected? | How |
|---|---|---|
| A secret left on the clipboard | ✅ | Cleared after 30 seconds (`STASH_CLIPBOARD_TIMEOUT`). |
| Clipboard history managers and Universal Clipboard (Handoff) | ✅ in the Mac app, ❌ in the CLI | The app marks copies `org.nspasteboard.ConcealedType` and `TransientType`, so well-behaved managers skip them, and keeps them on this Mac only (no Universal Clipboard). The CLI's `pbcopy` can't set those types. |
| Apps that read the clipboard while it holds the secret | ❌ | Any app can read the clipboard. Prefer `stash run` where you can. |

## The Mac app

`stash.app` is UI only. When it starts, it launches its own `stash app-server` child and talks to it with JSON-RPC over that process's stdin and stdout.

- **Only the app can talk to its backend.** There's no socket and no port. The pipes belong to the app.
- **The vault key stays in the backend.** It's held in the Rust process's memory, never sent to the app or to the session agent, and dropped on lock and after 10 idle minutes.
- **Values only on demand.**
  - Listing items and opening one never sends passwords, 2FA secrets, or notes to the app.
  - A value crosses over only when you click to reveal or copy it, one at a time.
  - Editing doesn't need values: untouched secret fields are saved as "keep".
- **Touch ID** works the same as in the CLI, through `stash-touchid` inside the bundle (`Contents/Helpers`).

| Threat | Protected? | How |
|---|---|---|
| Other apps reading the vault through the app | ✅ | No IPC endpoint exists. The backend is a private child process. |
| Secrets lingering in the app's memory | Partial | Only values you revealed or copied ever reach the app, and revealed values hide again after 30 seconds. Swift strings can't be reliably wiped, so a revealed value may stay in the app's memory until it's reused. |
| Showing a 2FA QR code for an authenticator app | Partial | The QR code contains the 2FA secret, because that's how authenticator apps import it, so anyone who sees or photographs it can generate your codes. It's fetched only when you click the QR button, is never shown as text, and closes after 60 seconds. |
| Scanning a 2FA QR code from the screen | ✅ | Scanning needs macOS's Screen Recording permission, which you grant once in System Settings. It runs only when you choose **Scan QR**. The capture leaves out stash's own windows, is decoded locally with Vision, and stays in memory: it's never written to disk or sent anywhere. Only an `otpauth://totp` code is used, and the backend validates it like a pasted one. Pasting or dropping an image needs no permission. |
| A modified `stash.app` | ❌ | The app is ad-hoc signed, so macOS can't vouch for who built it. Build it yourself from source, or wait for a signed and notarized release. |

## The MCP server (`stash mcp`)

AI agents talk to `stash mcp` over stdio. The design assumes the agent may be confused or manipulated, for example by prompt injection in a file it reads. So the agent is never the authority on what it may do. The user's fingerprint is.

- **Per-use approval:** every `run_with_secrets` and `request_secret` call needs a Touch ID match.
  - The system dialog shows the client's name, the exact command (sanitized and shortened), and the secret names.
  - The first request's unlock prompt counts as its approval, so there's one prompt per request, not two.
  - A declined request never starts its command.
- **No values in the conversation:** `run_with_secrets` returns output with injected values masked, and `request_secret` is off unless the server is started with `--allow-reveal`.
- **Allowlists:** with `--allow`, secrets outside the patterns are refused before any prompt, and the refusal is logged as `blocked`.
- **No shell sessions:** the server never creates or reuses agent sessions. It keeps the key in its own memory, which isn't reachable from the agent's shell commands, and forgets it after the idle timeout.
- **Bounded commands:** commands get no stdin, no `STASH_PASSWORD`, and their own process group, which is killed after the timeout. Output is capped at 64 KB per stream.
- **Audit log:** `audit.log` next to the vault, mode `0600`, one JSON line per request, with names and outcomes but never values.

| Threat | Protected? | How |
|---|---|---|
| A prompt-injected agent quietly using secrets | ✅ | Every use needs a fingerprint, on a dialog that shows the command and secrets. |
| An agent reading values from a command's output | Partial | Exact matches are masked. A command written to *transform* the secret (base64, reversing it) can leak it in that form, so read the command in the prompt before approving. |
| An agent using payment cards or bank accounts | ✅ | Refused unless the server is started with `--allow-payments`. They're also left out of `list_secrets`, and the refusal comes before any approval prompt, so you're never asked to approve a payment use you didn't expect. |
| An agent using secrets it shouldn't need | ✅ | `--allow` patterns. They work per **item**: allowing `github` also allows `github#notes`, custom fields, and live `#otp` codes. Keep 2FA and sensitive notes in separate items if an agent shouldn't reach them. |
| An agent reading the vault through its own shell | ✅ | Its shell commands have no session (see sessions above), and any `stash` call they make shows its own prompt naming the process chain. |
| Approving a request without reading it | ❌ | The prompt can only inform you. Check the command, especially `sh -c` scripts. |
| `--no-approval` | ❌ | It turns off the main protection. It exists only for headless setups with `STASH_PASSWORD`. |

## The SSH agent (`stash ssh agent`)

The agent serves the vault's SSH keys over the standard agent protocol on `~/.stash/ssh-agent.sock` (mode `0600`, in a `0700` directory). It answers only processes running as the same user.

- **Every signature needs Touch ID, on a prompt that names it.** The prompt says the key, what the data is for, and the requesting process chain (for example "sign a git commit or tag with SSH key “ssh/github”, for ssh-keygen ← git ← zsh").
  - The purpose is read from the data being signed: an SSH login names the remote user, and an `ssh-keygen -Y sign` signature names its namespace (`git` for commits). An `SSHSIG` signature can't double as a login, so the purpose can't be faked to get a login signed.
  - The user name and namespace come from the requesting program, so they're shown only if short and plain (letters, digits, `._@-`). Anything else is left out instead of being allowed to dress up the prompt.
  - When the vault is locked, the unlock prompt *is* the signature's prompt, so there's one prompt, not two. An unlock done for anything else, like listing keys, never approves a signature.
  - **Process names can be faked.** They come from the executable's name, so a program named `git` shows as `git`. Treat a prompt you didn't cause as suspicious whatever it says.
- **Declining pauses signing.** For 10 seconds after a declined prompt, every signature is refused without a prompt (logged as `blocked`), so a process can't keep asking until a prompt is approved out of habit.
- **Listing isn't secret.** After the first unlock, public keys stay listed even when the vault relocks (after `--lock-after`, 10 minutes by default), so `ssh` can choose a key without a prompt. The list is refreshed whenever the vault is unlocked, and lives only in the agent's memory.
- **No changes from outside.** Requests to add, remove, or lock keys, and protocol extensions, are refused. A compromised process can't plant its own key or wipe yours.
- **Keys stay in the vault.** Each signature decrypts the key, signs, and drops it. Keys are stored unencrypted *inside* the encrypted vault, so the agent never needs a passphrase. Imports read a passphrase only to decrypt the file, and refuse files asking for more than 2,000 bcrypt rounds (`ssh-keygen` uses 16), so a crafted file can't hang the import.
- **AI agents can't get private keys.** `stash mcp` doesn't list SSH items and refuses references to them before any prompt.
- **Audit log:** each signature, approved, declined, or failed, is logged by key name and purpose.

| Threat | Protected? | How |
|---|---|---|
| Malware quietly using your key (to push code, or log in to servers) | ✅ | Every signature needs a fingerprint, on a dialog naming the purpose and the process. |
| Stealing the key file | ✅ | There's no key file. Keys are only in the encrypted vault. |
| A rogue process adding its own key to the agent | ✅ | Add, remove, and lock requests are refused. |
| Agent forwarding (`ssh -A`) to a compromised server | Partial | The server can ask for signatures, but each one still needs your fingerprint, and the prompt shows the request came through `ssh`. Don't forward agents to hosts you don't trust. |
| Approving a prompt without reading it | ❌ | The prompt can only inform you. An unexpected prompt, especially one you didn't cause, should be declined. |
| `--no-approval` | ❌ | It turns off the main protection. It exists only for headless setups with `STASH_PASSWORD`. |

Git signing uses a small wrapper (`~/.stash/git-ssh-sign`) that runs `ssh-keygen` with the agent's socket, so `SSH_AUTH_SOCK` doesn't have to change for the rest of the system.

## Browser autofill

The browser extension fills pages; the vault and every rule stay in `stash native-host`, which the browser starts over native messaging.

- **Only a real browser reaches the host.** The host checks the process that started it: on macOS, a browser app with a valid code signature whose Team ID *and* app identifier are on a fixed list (`com.google.Chrome`, `org.mozilla.firefox`, `com.brave.Browser`, `com.microsoft.edgemac`, `company.thebrowser.Browser`, and the Chrome, Brave, and Edge beta/dev channels; not Firefox Developer Edition or Nightly, which can be set to run unsigned add-ons). The Team alone isn't enough: Google also signs Chrome for Testing, which loads any extension from the command line, and a rogue extension can copy stash's public manifest key to get stash's ID. If the parent is a helper, it must be one inside that same browser app, signed by the same maker, so another extension's native helper can't pass itself off as the browser. On Linux, a root-owned system browser. The prompt names the actual app. A program that runs `stash native-host` itself is refused before it can ask for anything.
- **A changed extension is refused.** Browsers don't verify unpacked extensions, so the host compares `~/.stash/browser-extension` with the copy built into `stash` and refuses everything if a file was changed or added. (An extension loaded from somewhere else can't be checked; store-signed releases will close this.)
- **Logins fill only on their site.** A login fills only where a saved website matches the page by registrable domain (Public Suffix List), compared in punycode, on https pages (or `localhost`). The check runs in the host on every fill, not only when suggesting, and the page address comes from the browser, not from the page.
- **One unlock covers logins everywhere, and says so.** The unlock prompt reads "unlock stash for autofill in Google Chrome: logins on any site for the next 10 minutes, starting with github.com", because that's what it allows.
- **Payments always ask.** Every card or bank fill needs Touch ID, on a prompt naming the item and the site, even while unlocked. A fill that arrives while locked unlocks with that same prompt. After a declined prompt, payment fills are refused for 10 seconds.
- **Fills need a click in stash's own interface.** By default there's no content script on any page: the extension uses `activeTab`, so it can touch only the tab whose toolbar button you clicked. Pages can't message the extension.
- **Sign-in field icons and saving (opt-in).** Turning on *Show stash in sign-in fields* grants access to https sites (and `localhost`) and registers a content script; turning it off removes both.
  - The content script draws only a small button, in a closed shadow root. The button opens the stash menu only for a trusted click (`isTrusted`), and the menu is an extension page in a frame, so the page can't read it, script it, or forge a choice in it. Fills from the menu follow every rule above.
  - The content script may send the background exactly one kind of message: "a form was submitted with this username and password", from the page itself or a same-origin frame. The background asks the host whether it's already saved (`check_saved` returns only new/same/changed/locked) and, if not, shows stash's own save prompt, also an extension page in a frame. Only a click there saves.
  - **A save only ever affects the page's own site.** The host creates a login named after the page's registrable domain with the page's origin as its website, or updates the login already saved for that site and username. A page can't overwrite another site's login. Updates keep the replaced password in the item.
  - Pending sign-ins are held in the background's memory only, for at most 3 minutes.
- **Frames.** Logins fill only in frames of exactly the approved origin. Cards also fill in the card frames of two payment processors (Stripe, Braintree), only on https pages, and only when that frame sits *directly* in the approved page (its parent is the top page, and where the browser reports ancestors, the nearest one is the approved origin), never nested inside another frame like an ad. Each frame is asked first whether it may be filled; values are sent only to the frames that may.
- **Navigation during Touch ID.** If the tab moved to another site while the prompt was up, nothing is filled.
- **Hidden fields are never filled.** Fields must be visible (size, `display`, `visibility`, opacity), enabled, and editable, in a visible document.
- **Nothing kept in the browser.** The extension has no storage. Values go from the host straight into the page.
- **Audit:** each fill, and each refusal, is logged by item name and site.

| Threat | Protected? | How |
|---|---|---|
| A phishing site (`github.com.evil.io`, `githuЬ.com`) | ✅ | Registrable-domain matching in punycode; the login isn't even suggested. |
| A malicious page triggering a fill | ✅ | Fills start only from a click in stash's popup or in-page menu (an extension frame the page can't script). |
| A malicious page faking a sign-in to plant or change a saved login | Partial | It can make stash *offer* to save, but only for its own site, and only your click in stash's prompt saves. Another site's logins can't be touched; a changed password keeps the old one. |
| A page detecting that stash is installed | ❌ (opt-in mode) | With field icons on, the page can see stash's element in the DOM. |
| Invisible forms harvesting autofill | ✅ | Hidden and zero-size fields are skipped. |
| A malicious page reading a payment card | Partial | A card fills only after a Touch ID prompt naming the site, so read it. After filling, the page has what it asked for, as with typing it yourself. |
| A program running `stash native-host` to read the vault | ✅ | Refused unless started by a signed browser. |
| A program starting `stash native-host` from inside the browser (another extension's helper) | ✅ | Only the browser itself, or one of its own signed helpers, may be the parent. |
| An automation build of a browser (Chrome for Testing) with a rogue extension using stash's ID | ✅ | The app identifier must be on the list, not just the maker's Team ID. |
| A program launching a separate Firefox with a temporary add-on that claims stash's ID | Partial | Release Firefox loads temporary add-ons through its remote-debugging interface, and a Firefox add-on ID isn't tied to a key, so such an add-on can reach the host. It still needs your Touch ID to unlock, on a prompt naming Firefox; if you're not using Firefox right then, decline. Store-signed releases with a key-bound channel are planned. |
| Edited files in the unpacked extension | Partial | Detected for `~/.stash/browser-extension`; not for an extension loaded from elsewhere. |
| A compromised browser, or a program adding an extension to your browser profile | ❌ | The browser sees what it fills. |

**Idle locks** in the Mac app, `stash mcp`, the SSH agent, and the browser bridge are checked when the next request arrives: the main key stays in that process's memory until then (never the sensitive key, which each of them forgets right after use).

## Planned features and their open questions

- **Repeated approvals:** a prompt for every agent request is safe but can get tiring. A future option may let you approve one exact command for a few minutes.
- **Programs started directly from the unlocked shell** can still use its session (see sessions above). Tighter options, like checking the requesting executable or binding sessions to a terminal device, are being considered.
- **Linux:** there's no Touch ID equivalent yet, so `stash mcp`, SSH agent, and browser autofill approvals only work on macOS for now.
- **SSH approvals for a while:** a prompt per signature is the safe default. A future option may approve one key for one program for a few minutes, as 1Password does.
- **More SSH key types:** RSA and ECDSA keys aren't supported yet; Ed25519 is what GitHub, GitLab, and `ssh-keygen` recommend.
