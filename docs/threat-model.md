# Threat model

This document covers what stash protects against, how it does it, and what it doesn't protect against. It describes **v0.4**: an encrypted vault file, a CLI, Touch ID unlock, sessions scoped to your shell, `stash run` / `stash inject`, and the MCP server for AI agents.

## What we protect

The names and values of the secrets in your vault.

## Vault format (version 1)

The vault is a single SQLite file, `~/.stash/vault.db` by default.

| Piece | How it's protected |
|---|---|
| Master password | Never stored. It goes through **Argon2id** (64 MiB, 3 passes, 1 lane) with a random 16-byte salt to produce a key-encryption key (KEK). |
| Vault key | 32 random bytes from the operating system's random number generator, encrypted with the KEK using **XChaCha20-Poly1305**. The encryption is bound to the format version, the KDF parameters, and the salt, so none of them can be changed without being detected. |
| Secret names | Never stored in plaintext. Each row's id is `HMAC-SHA256(index_key, name)`, where `index_key` is derived from the vault key. The name is also encrypted along with the value. |
| Secret values | Encrypted together with the name using XChaCha20-Poly1305 and the vault key. Each one gets a fresh random 24-byte nonce, and the row id is bound into the encryption, so an encrypted value can't be moved to a different row. |
| Deleted secrets | SQLite's `secure_delete` setting overwrites freed pages with zeros. |
| File permissions | The vault file is created with mode `0600`, and new parent directories with `0700`. |

Because of this design, changing the master password (not yet available as a command) will only need to re-encrypt the vault key, not every secret.

## Threats and how stash handles them

| Threat | Protected? | How |
|---|---|---|
| Someone copies your vault file (stolen laptop backup, synced folder, etc.) | ✅ | Without the master password they only have ciphertext. Argon2id makes guessing the password slow and expensive. |
| Someone edits the vault file (changes, swaps, or truncates rows, or tampers with the KDF settings) | ✅ detected | Authenticated encryption makes stash refuse to open or read anything that was modified. It **can't** stop someone deleting the whole file, so keep backups. |
| Someone learns what services you use from the secret names | ✅ | Names are encrypted. The number of items and their approximate sizes are still visible. |
| Other user accounts on the same Mac | ✅ | File permissions keep them out. |
| Secrets left lying around in memory | Partial | Keys, passwords, and values are wiped when they're no longer needed (`zeroize`). But temporary copies made by the OS, the terminal, or growing buffers can't all be guaranteed wiped. |
| Weak master password | Partial | stash requires at least 8 characters and Argon2id slows guessing down. A short password can still be cracked offline. Use a long passphrase. |

## What stash does *not* protect against

- **Malware running as your user.** It can read your keystrokes, read process memory, or just run `stash get`. No local password manager can fully defend against this.
- **`STASH_PASSWORD`.** If you set this environment variable, any process that can read your environment can read your master password. It's meant only for scripts and CI.
- **Secrets after you use them.** Once `stash get` prints a value, stash can't control what your shell, terminal scrollback, or the receiving program does with it. The planned `stash run` reduces this exposure.
- **Losing your master password.** There's no recovery. Without the password, the vault can't be opened.

## Touch ID unlock (macOS)

`stash touchid enable` asks for the master password once. Then the `stash-touchid` helper:

1. creates a P-256 key **inside the Secure Enclave**, with the access control `privateKeyUsage + biometryCurrentSet`
2. encrypts the vault key to that key: an ephemeral ECDH key exchange, HKDF-SHA256, and ChaCha20-Poly1305
3. saves the result as `<vault>.touchid` (mode `0600`). The file holds the encrypted vault key and an encrypted handle to the Secure Enclave key, which is useless on any other Mac.

To unlock, the helper asks for a fingerprint and then has the Secure Enclave do the key exchange. The vault key is passed back to `stash` over a pipe, never as a command-line argument. Before using the key, `stash` checks it against the vault's key check (an HMAC of the vault key), so a stale or swapped `.touchid` file is rejected.

| Threat | Protected? | How |
|---|---|---|
| Someone copies `vault.db` and `vault.db.touchid` to another machine | ✅ | The Secure Enclave key can't leave this Mac's chip, so the `.touchid` file is useless elsewhere. They're left with the master-password protection described above. |
| Someone with your unlocked Mac but not your finger | ✅ | The Secure Enclave won't use the key without a fingerprint match. |
| Someone enrolls their own fingerprint on your Mac | ✅ | `biometryCurrentSet` makes the key unusable after any fingerprint change. Run `stash touchid enable` again (with the master password). |
| Malware running as your user | ❌ | It can trigger the Touch ID prompt, so look closely at what the dialog says. The prompt comes from `stash-touchid`. |

## Unlocked sessions (the agent)

After an unlock, `stash` starts `stash agent` in the background. The agent keeps the vault key in memory so one fingerprint covers several commands, but only for the process that unlocked.

- **Socket:** `~/.stash/agent.sock`, mode `0600`, inside the `0700` directory `~/.stash`.
- **Same-user check:** the agent checks every connection's user id (`getpeereid` / `SO_PEERCRED`) and ignores other users.
- **Sessions are scoped to the unlocking process's parent.** When `stash` hands the agent a key, the agent asks the kernel which process connected (`LOCAL_PEERPID` / `SO_PEERCRED`). It records that process's parent, usually your shell, by pid *and* start time. A later request gets the key only if the requester's parent is that same process. A recycled pid doesn't match, because its start time differs. Callers never state who they are: it all comes from the kernel.
- **Anyone else unlocks for themselves.** The prompt names the request and the process chain behind it, so an unexpected prompt is visible.
- **Timeout:** each key is forgotten after 10 minutes without use (`STASH_SESSION_TIMEOUT`). `stash lock` forgets all keys immediately. The agent exits once it holds no keys.
- **Memory only:** keys are never written to disk and are wiped from memory when dropped.

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
| An agent using secrets it shouldn't need | ✅ | `--allow` patterns. |
| An agent reading the vault through its own shell | ✅ | Its shell commands have no session (see sessions above), and any `stash` call they make shows its own prompt naming the process chain. |
| Approving a request without reading it | ❌ | The prompt can only inform you. Check the command, especially `sh -c` scripts. |
| `--no-approval` | ❌ | It turns off the main protection. It exists only for headless setups with `STASH_PASSWORD`. |

## Planned features and their open questions

- **Repeated approvals:** a prompt for every agent request is safe but can get tiring. A future option may let you approve one exact command for a few minutes.
- **Programs started directly from the unlocked shell** can still use its session (see sessions above). Tighter options, like checking the requesting executable or binding sessions to a terminal device, are being considered.
- **Linux:** there's no Touch ID equivalent yet, so `stash mcp` approvals only work on macOS for now.
