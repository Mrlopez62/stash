# Threat model

This document covers what stash protects against, how it does it, and what it doesn't protect against. It describes **v0.1**: an encrypted vault file plus a CLI that asks for the master password. Each later feature (Touch ID, the background agent, MCP) will add its own section here.

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

## Planned features and their open questions

- **Touch ID (v0.2):** the vault key will be stored in the macOS Keychain behind a `biometryCurrentSet` access control, with session lifetime handled by the background agent. Each part will get its own threat-model section before it ships.
- **MCP server (v0.4):** AI agents will get secret names and the ability to run commands with secrets filled in, not the values themselves. Getting a raw value will need approval each time. Leaks through command output are a known risk, and the plan is to mask secret values in output on a best-effort basis.
