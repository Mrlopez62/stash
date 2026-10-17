# Threat model

This document covers what stash protects against, how it does it, and what it doesn't protect against. It describes **v0.2**: an encrypted vault file, a CLI, Touch ID unlock, and unlocked sessions. Each later feature (such as MCP) will add its own section here.

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

After an unlock, `stash` starts `stash agent` in the background. The agent keeps the vault key in memory and gives it to later `stash` commands, so one fingerprint covers several commands.

- **Socket:** `~/.stash/agent.sock`, mode `0600`, inside the `0700` directory `~/.stash`.
- **Same-user check:** the agent checks every connection's user id (`getpeereid` / `SO_PEERCRED`) and ignores other users.
- **Timeout:** each key is forgotten after 10 minutes without use (`STASH_SESSION_TIMEOUT`). `stash lock` forgets all keys immediately. The agent exits once it holds no keys.
- **Memory only:** keys are never written to disk and are wiped from memory when dropped.

| Threat | Protected? | How |
|---|---|---|
| Other user accounts | ✅ | Socket permissions plus the user id check on every connection. |
| A forgotten unlocked session | Partial | It ends by itself after 10 idle minutes, and `stash lock` ends it at once. |
| Malware running as your user *during* a session | ❌ | It can ask the agent for the key, just as it could ask `ssh-agent` to sign. Set `STASH_SESSION_TIMEOUT=0` if you'd rather confirm every command. |

## Planned features and their open questions

- **MCP server (v0.4):** AI agents will get secret names and the ability to run commands with secrets filled in, not the values themselves. Getting a raw value will need approval each time. Leaks through command output are a known risk, and the plan is to mask secret values in output on a best-effort basis.
- **Per-session approval:** a future version may scope sessions to one terminal or process tree, rather than to your whole user account.
