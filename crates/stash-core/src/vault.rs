//! The on-disk vault: a SQLite file holding password-wrapped keys and
//! individually encrypted items.
//!
//! Layout (format version 3):
//!
//! - **Two random keys**, each wrapped with the Argon2id key-encryption key
//!   (KEK) derived from the master password, bound to the header (version,
//!   KDF parameters, salt):
//!   - the *main key*, which reads every item's name and non-secret parts;
//!     sessions and Touch ID unlocks hold it;
//!   - the *sensitive key*, which alone reads the secret values of cards,
//!     bank accounts, and SSH keys. It's never kept by a session: each use
//!     needs a fresh Touch ID or master password.
//! - **Subkeys** derived from the main key (HMAC-SHA256 with distinct
//!   labels): one encrypts items, one makes row ids, one authenticates the
//!   whole vault, one checks that a key belongs to this vault.
//! - `items`: one row per item. The row id is `HMAC(index key, name)`, so
//!   names are never stored in plaintext. `blob` is the name and contents
//!   sealed (XChaCha20-Poly1305) with the item key, bound to the row id. For
//!   sensitive kinds, `blob` holds a *redacted* copy (labels, non-secret
//!   values, "Visa •••• 4242") and `secret` the full item, sealed with the
//!   sensitive key.
//! - **A vault-wide MAC** over every row (id and hashes of both blobs) and a
//!   write counter, updated in the same transaction as every write and
//!   checked on every open. Removing, adding, or rolling back individual
//!   items is detected. (Replacing the *whole* file with an older copy of
//!   itself isn't: that copy is self-consistent. It's protected by the
//!   password that was current when it was made.)
//!
//! Item plaintext encodings:
//! - **secret**: `u16 name length (LE) || name || raw value`. Any bytes.
//! - **structured**: `0xFFFF || u16 name length || name || JSON item`.
//! - **redacted** (v3, sensitive kinds' `blob`): `0xFFFE || ...` as above.
//!
//! Versions 1 and 2 (one key, no MAC) still open, read-only: unlocking with
//! the master password upgrades them to version 3, after copying the old
//! file to a backup next to it.

use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use secrecy::SecretSlice;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, SALT_LEN, SecretKey};
use crate::item::{FieldValue, Item, Kind};
use crate::reference::Reference;
use crate::{Error, Result, validate_name};

const FORMAT_VERSION: i64 = 3;
const OLDEST_SUPPORTED_VERSION: i64 = 1;
/// Marks the structured encoding (see the module docs).
const STRUCTURED: [u8; 2] = [0xFF, 0xFF];
/// Marks the redacted copy of a sensitive item.
const REDACTED: [u8; 2] = [0xFF, 0xFE];

/// The most a vault header may ask Argon2 for, checked *before* deriving,
/// so an edited file can't make an unlock exhaust memory: 4 GiB, 16 passes,
/// 16 lanes.
const MAX_KDF: KdfParams = KdfParams {
    m_cost_kib: 4 * 1024 * 1024,
    t_cost: 16,
    p_cost: 16,
};

/// One row of a listing: enough for `stash ls --long` or the app's sidebar,
/// without any secret values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub name: String,
    pub kind: Kind,
    pub username: Option<String>,
    pub url: Option<String>,
    pub has_otp: bool,
    pub updated: u64,
    /// For cards and bank accounts: "Visa •••• 4242 · 08/27". Never more
    /// than the last four digits.
    pub subtitle: Option<String>,
}

const SCHEMA: &str = "
    CREATE TABLE meta  (key TEXT PRIMARY KEY, value ANY NOT NULL) STRICT;
    CREATE TABLE items (id BLOB PRIMARY KEY, blob BLOB NOT NULL, secret BLOB) STRICT;
";

/// The keys derived from the main key.
struct Keys {
    main: SecretKey,
    /// Seals items' `blob`.
    item: SecretKey,
    /// Makes row ids from names.
    index: SecretKey,
    /// Authenticates the whole vault (v3).
    mac: SecretKey,
    /// Version 1 and 2 vaults used the main key directly.
    legacy: bool,
}

impl Keys {
    fn new(main: SecretKey, version: i64) -> Self {
        let derive = |label: &[u8]| Zeroizing::new(crypto::hmac(main.as_ref(), label));
        if version >= 3 {
            Self {
                item: derive(b"stash/v3/item-key"),
                index: derive(b"stash/v3/index-key"),
                mac: derive(b"stash/v3/vault-mac-key"),
                main,
                legacy: false,
            }
        } else {
            Self {
                item: Zeroizing::new(*main),
                index: derive(b"stash/index-key/v1"),
                mac: Zeroizing::new([0u8; crypto::KEY_LEN]),
                main,
                legacy: true,
            }
        }
    }

    /// Proves a main key belongs to this vault without revealing it.
    fn check(&self) -> [u8; 32] {
        let label: &[u8] = if self.legacy {
            b"stash/key-check/v1"
        } else {
            b"stash/v3/key-check"
        };
        crypto::hmac(self.main.as_ref(), label)
    }

    fn item_aad(&self, id: &[u8]) -> Vec<u8> {
        let mut aad = if self.legacy {
            b"stash/item/v1".to_vec()
        } else {
            b"stash/v3/item".to_vec()
        };
        aad.extend_from_slice(id);
        aad
    }
}

/// The sensitive key's own subkey and check value.
fn sensitive_item_key(sensitive: &SecretKey) -> SecretKey {
    Zeroizing::new(crypto::hmac(
        sensitive.as_ref(),
        b"stash/v3/sensitive-item-key",
    ))
}

fn sensitive_check(sensitive: &SecretKey) -> [u8; 32] {
    crypto::hmac(sensitive.as_ref(), b"stash/v3/sensitive-key-check")
}

fn sensitive_aad(id: &[u8]) -> Vec<u8> {
    let mut aad = b"stash/v3/sensitive-item".to_vec();
    aad.extend_from_slice(id);
    aad
}

/// An unlocked vault. Keys are wiped from memory when this is dropped.
pub struct Vault {
    conn: Connection,
    keys: Keys,
    /// The sensitive key, if this unlock may read sensitive items (a master
    /// password unlock, or [`Vault::unlock_sensitive`]).
    sensitive: Option<SecretKey>,
    path: PathBuf,
    version: i64,
    /// A master-password unlock tried to upgrade the vault but couldn't,
    /// because the file is read-only or in use.
    upgrade_blocked: bool,
    /// Where the pre-upgrade copy went, if this unlock upgraded the vault.
    backup: Option<PathBuf>,
    /// Why an upgrade attempt failed (other than a read-only file).
    upgrade_problem: Option<String>,
}

/// A stored row: the item's `blob`, and for sensitive kinds its `secret`.
type Row = (Vec<u8>, Option<Vec<u8>>);

/// What a master-password unlock found in the header.
struct Unwrapped {
    main: SecretKey,
    sensitive: Option<SecretKey>,
    params: KdfParams,
}

impl Vault {
    /// Create a new, empty vault at `path`, protected by `password`.
    ///
    /// Fails with [`Error::VaultExists`] if a file is already there. On Unix the
    /// file is created with mode `0600` and missing parent directories `0700`.
    pub fn create(path: &Path, password: &[u8], params: KdfParams) -> Result<Self> {
        check_kdf(params)?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            create_private_dir(parent)?;
        }
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        match opts.open(path) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                return Err(Error::VaultExists(path.to_owned()));
            }
            Err(e) => return Err(e.into()),
        }

        let result = (|| {
            let mut conn = connect(path)?;
            conn.execute_batch(SCHEMA)?;
            let main = crypto::random_key()?;
            let sensitive = crypto::random_key()?;
            let tx = conn.transaction()?;
            write_header(&tx, password, params, &main, &sensitive)?;
            let keys = Keys::new(main, FORMAT_VERSION);
            bump_mac(&tx, &keys)?;
            tx.commit()?;
            let vault = Self::from_parts(conn, keys, Some(sensitive), path, FORMAT_VERSION);
            vault.publish_audit_key();
            Ok(vault)
        })();
        if result.is_err() {
            let _ = fs::remove_file(path);
        }
        result
    }

    /// Open and unlock an existing vault with the master password. This
    /// unlock can read sensitive items too. A version 1 or 2 vault is
    /// upgraded to version 3 (after a backup copy), and weaker-than-default
    /// KDF settings are strengthened.
    pub fn open(path: &Path, password: &[u8]) -> Result<Self> {
        let (mut conn, version) = connect_existing(path)?;
        let found = unwrap_header(&conn, version, password)?;

        if version < FORMAT_VERSION {
            let legacy = Keys::new(Zeroizing::new(*found.main), version);
            return match tolerate_unwritable(upgrade(&mut conn, path, &legacy, password)) {
                // Another stash process upgraded it first: open the result.
                Ok(Some(None)) => {
                    drop(conn);
                    Vault::open(path, password)
                }
                Ok(Some(Some((keys, sensitive, backup)))) => {
                    let mut vault =
                        Self::from_parts(conn, keys, Some(sensitive), path, FORMAT_VERSION);
                    vault.backup = Some(backup);
                    vault.publish_audit_key();
                    Ok(vault)
                }
                Ok(None) => {
                    let mut vault = Self::from_parts(conn, legacy, None, path, version);
                    vault.upgrade_blocked = true;
                    Ok(vault)
                }
                // A backup that couldn't be made (a full disk, say) still
                // lets the old vault open, read-only.
                Err(Error::UpgradeFailed(why)) => {
                    let mut vault = Self::from_parts(conn, legacy, None, path, version);
                    vault.upgrade_problem = Some(why);
                    Ok(vault)
                }
                Err(e) => Err(e),
            };
        }

        let keys = Keys::new(Zeroizing::new(*found.main), version);
        let sensitive = found
            .sensitive
            .ok_or_else(|| Error::Corrupt("missing the sensitive key".into()))?;
        // One read transaction, so a concurrent write can't make the
        // checks see two different states (a false "tampered").
        {
            let snapshot = conn.unchecked_transaction()?;
            verify_key_check(&snapshot, &keys)?;
            verify_mac(&snapshot, &keys)?;
            verify_sensitive_check(&snapshot, &sensitive)?;
            snapshot.commit()?;
        }

        // Re-wrap both keys with stronger KDF settings if these are weaker
        // than today's defaults. Tolerates a read-only or busy file.
        // Best effort, and under the same lock and checks as any write, so
        // it can never put back keys another process just replaced.
        if weaker_than(found.params, strengthen_target()) {
            let _ = (|| -> Result<()> {
                let tx = begin_write(&mut conn, &keys, Some(&sensitive))?;
                let current = KdfParams {
                    m_cost_kib: meta(&tx, "kdf_m_cost_kib")?,
                    t_cost: meta(&tx, "kdf_t_cost")?,
                    p_cost: meta(&tx, "kdf_p_cost")?,
                };
                if weaker_than(current, strengthen_target()) {
                    write_header(&tx, password, strengthen_target(), &keys.main, &sensitive)?;
                    tx.commit()?;
                }
                Ok(())
            })();
        }
        let vault = Self::from_parts(conn, keys, Some(sensitive), path, version);
        vault.publish_audit_key();
        Ok(vault)
    }

    /// Open an existing vault with its main key, as handed back by Touch ID
    /// or the session agent. Fails with [`Error::WrongKey`] if the key
    /// doesn't belong to this vault. This unlock can't read sensitive items
    /// until [`Vault::unlock_sensitive_with_key`] or
    /// [`Vault::unlock_sensitive`].
    pub fn open_with_key(path: &Path, key: &[u8; crypto::KEY_LEN]) -> Result<Self> {
        let (conn, version) = connect_existing(path)?;
        let keys = Keys::new(Zeroizing::new(*key), version);
        {
            let snapshot = conn.unchecked_transaction()?;
            verify_key_check(&snapshot, &keys)?;
            if !keys.legacy {
                verify_mac(&snapshot, &keys)?;
            }
            snapshot.commit()?;
        }
        let vault = Self::from_parts(conn, keys, None, path, version);
        vault.publish_audit_key();
        Ok(vault)
    }

    fn from_parts(
        conn: Connection,
        keys: Keys,
        sensitive: Option<SecretKey>,
        path: &Path,
        version: i64,
    ) -> Self {
        Self {
            conn,
            keys,
            sensitive,
            path: path.to_owned(),
            version,
            upgrade_blocked: false,
            backup: None,
            upgrade_problem: None,
        }
    }

    /// Whether the vault is in the current format, so it can be changed.
    pub fn is_current(&self) -> bool {
        self.version >= FORMAT_VERSION
    }

    /// Why the vault can't be changed yet.
    pub fn upgrade_error(&self) -> Error {
        if let Some(why) = &self.upgrade_problem {
            Error::UpgradeFailed(why.clone())
        } else if self.upgrade_blocked {
            Error::UpgradeBlocked
        } else {
            Error::NeedsUpgrade
        }
    }

    /// If this unlock upgraded the vault: where the old file was copied.
    pub fn upgrade_backup(&self) -> Option<&Path> {
        self.backup.as_deref()
    }

    /// The audit log's secret key: the log is sealed to its public key
    /// (see [`Vault::audit_public_key`]), so only an unlocked vault can
    /// read it.
    pub fn audit_secret(&self) -> Result<SecretKey> {
        self.subkey(b"stash/v3/audit-key")
    }

    /// The public key the audit log is sealed to, as published in the
    /// vault file by the last unlock. Needs no password, so processes can
    /// add to the log while locked. `None` until a current-format vault
    /// has been unlocked once.
    pub fn audit_public_key(path: &Path) -> Result<Option<[u8; 32]>> {
        if !path.exists() {
            return Err(Error::VaultMissing(path.to_owned()));
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let found: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'audit_public_key'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.and_then(|key| key.try_into().ok()))
    }

    /// A tag only this vault's key can make, for remembering decisions
    /// outside the vault (like trusted `.env` files) so they can't be
    /// forged.
    pub fn trust_tag(&self, data: &[u8]) -> Result<[u8; 32]> {
        Ok(crypto::hmac(
            self.subkey(b"stash/v3/trust-key")?.as_ref(),
            data,
        ))
    }

    fn subkey(&self, label: &[u8]) -> Result<SecretKey> {
        if self.keys.legacy {
            return Err(self.upgrade_error());
        }
        Ok(Zeroizing::new(crypto::hmac(self.keys.main.as_ref(), label)))
    }

    /// Put the audit log's public key in the vault file (if it's missing
    /// or was replaced), so locked processes seal log lines to the right
    /// key. Best effort: a read-only or busy vault is left alone.
    fn publish_audit_key(&self) {
        let Ok(secret) = self.audit_secret() else {
            return;
        };
        let public = crypto::x25519_public(&secret);
        let stored: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'audit_public_key'",
                [],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten();
        if stored.as_deref() != Some(public.as_slice()) {
            let _ = self.conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('audit_public_key', ?1)",
                [public.as_slice()],
            );
        }
    }

    /// Whether an item with this name exists.
    pub fn contains(&self, name: &str) -> Result<bool> {
        validate_name(name)?;
        Ok(self.row(&self.item_id(name))?.is_some())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The main key, for handing to Touch ID enrollment or the session
    /// agent. Treat it like the master password.
    pub fn key(&self) -> &[u8; crypto::KEY_LEN] {
        &self.keys.main
    }

    /// The sensitive key, if this unlock holds it (for Touch ID
    /// enrollment). Never give it to a session.
    pub fn sensitive_key(&self) -> Option<&[u8; crypto::KEY_LEN]> {
        self.sensitive.as_deref()
    }

    /// Whether sensitive items can be read or written right now.
    pub fn has_sensitive(&self) -> bool {
        self.sensitive.is_some()
    }

    /// Unlock sensitive items with the master password.
    pub fn unlock_sensitive(&mut self, password: &[u8]) -> Result<()> {
        let found = unwrap_header(&self.conn, self.version, password)?;
        if !crypto::ct_eq(found.main.as_ref(), self.keys.main.as_ref()) {
            return Err(Error::WrongPassword);
        }
        let sensitive = found
            .sensitive
            .ok_or_else(|| Error::Corrupt("missing the sensitive key".into()))?;
        verify_sensitive_check(&self.conn, &sensitive)?;
        self.sensitive = Some(sensitive);
        Ok(())
    }

    /// Unlock sensitive items with the sensitive key (from Touch ID).
    pub fn unlock_sensitive_with_key(&mut self, key: &[u8; crypto::KEY_LEN]) -> Result<()> {
        let sensitive = Zeroizing::new(*key);
        verify_sensitive_check(&self.conn, &sensitive)?;
        self.sensitive = Some(sensitive);
        Ok(())
    }

    /// Forget the sensitive key: long-lived processes call this after each
    /// use, so a sensitive value always needs a fresh approval.
    pub fn lock_sensitive(&mut self) {
        self.sensitive = None;
    }

    /// Store a single-value secret. Fails with [`Error::AlreadyExists`]
    /// unless `overwrite` is set.
    pub fn add(&mut self, name: &str, value: &[u8], overwrite: bool) -> Result<()> {
        validate_name(name)?;
        if !self.is_current() {
            return Err(self.upgrade_error());
        }
        let payload = encode_secret(name, value);
        self.write(name, &payload, None, overwrite)
    }

    /// Store an item. A plain secret (one value, no notes) uses the secret
    /// encoding; everything else the structured one. Cards, bank accounts,
    /// and SSH keys need the sensitive key ([`Error::SensitiveLocked`]
    /// otherwise). `updated` is set to now, and `created` too if it's 0.
    pub fn put(&mut self, name: &str, item: &Item, overwrite: bool) -> Result<()> {
        validate_name(name)?;
        // Normalized and checked here, not just in each client, so any edit
        // is caught.
        let mut item = item.clone();
        item.summary = None;
        item.normalize();
        item.validate()?;
        let plain_secret =
            item.kind == Kind::Secret && item.fields.len() == 1 && item.notes.is_empty();
        if plain_secret {
            let value = item.primary().unwrap_or("");
            return self.add(name, value.as_bytes(), overwrite);
        }
        if !self.is_current() {
            return Err(self.upgrade_error());
        }
        let now = unix_now();
        item.updated = now;
        if item.created == 0 {
            item.created = now;
        }
        if item.kind.is_sensitive() {
            if self.sensitive.is_none() {
                return Err(Error::SensitiveLocked(name.to_owned()));
            }
            let public = encode_with(&REDACTED, name, &item.redacted())?;
            let secret = encode_with(&STRUCTURED, name, &item)?;
            self.write(name, &public, Some(&secret), overwrite)
        } else {
            let payload = encode_with(&STRUCTURED, name, &item)?;
            self.write(name, &payload, None, overwrite)
        }
    }

    fn write(
        &mut self,
        name: &str,
        payload: &[u8],
        secret: Option<&[u8]>,
        overwrite: bool,
    ) -> Result<()> {
        let id = self.item_id(name);
        let blob = crypto::seal(&self.keys.item, &self.keys.item_aad(&id), payload)?;
        let sealed_secret = match secret {
            Some(secret) => {
                let key = sensitive_item_key(self.sensitive.as_ref().expect("checked by put"));
                Some(crypto::seal(&key, &sensitive_aad(&id), secret)?)
            }
            None => None,
        };
        let tx = begin_write(&mut self.conn, &self.keys, self.sensitive.as_ref())?;
        let exists = tx
            .query_row(
                "SELECT 1 FROM items WHERE id = ?1",
                params![id.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if exists && !overwrite {
            return Err(Error::AlreadyExists(name.to_owned()));
        }
        tx.execute(
            "INSERT INTO items (id, blob, secret) VALUES (?1, ?2, ?3)
             ON CONFLICT (id) DO UPDATE SET blob = excluded.blob, secret = excluded.secret",
            params![id.as_slice(), blob, sealed_secret],
        )?;
        bump_mac(&tx, &self.keys)?;
        tx.commit()?;
        Ok(())
    }

    /// Read an item's main value: a secret's value, a login's password, a
    /// note's text, a card's number.
    pub fn get(&self, name: &str) -> Result<SecretSlice<u8>> {
        match self
            .stored(name, true)?
            .ok_or_else(|| Error::NotFound(name.to_owned()))?
        {
            Stored::Secret(value) => Ok(SecretSlice::from(value.to_vec())),
            Stored::Structured(item) | Stored::Redacted(item) => item
                .primary()
                .map(|v| SecretSlice::from(v.as_bytes().to_vec()))
                .ok_or_else(|| Error::NoSuchField(name.to_owned(), "password".into())),
        }
    }

    /// Read a whole item. Single-value secrets come back as `Kind::Secret`
    /// items; binary ones fail with [`Error::NotText`] (use [`Vault::get`]).
    /// Sensitive items need the sensitive key ([`Error::SensitiveLocked`]).
    pub fn item(&self, name: &str) -> Result<Item> {
        self.item_inner(name, true)
    }

    /// Read an item for display: like [`Vault::item`], but a sensitive item
    /// comes back redacted (see [`Item::redacted`]) when the sensitive key
    /// isn't held, instead of failing.
    pub fn item_redacted(&self, name: &str) -> Result<Item> {
        self.item_inner(name, false)
    }

    fn item_inner(&self, name: &str, full: bool) -> Result<Item> {
        match self
            .stored(name, full)?
            .ok_or_else(|| Error::NotFound(name.to_owned()))?
        {
            Stored::Secret(value) => {
                // Check before copying, so a failed conversion leaves no copy.
                let text =
                    std::str::from_utf8(&value).map_err(|_| Error::NotText(name.to_owned()))?;
                Ok(Item::secret(text))
            }
            Stored::Structured(item) | Stored::Redacted(item) => Ok(item),
        }
    }

    /// Resolve a `stash://name` or `stash://name#field` reference. An OTP
    /// field yields its current code for `unix_time`.
    pub fn resolve(&self, reference: &Reference, unix_time: u64) -> Result<Zeroizing<Vec<u8>>> {
        let Some(selector) = reference.field else {
            use secrecy::ExposeSecret;
            return Ok(Zeroizing::new(
                self.get(reference.name)?.expose_secret().to_vec(),
            ));
        };
        let item = self.item(reference.name)?;
        let missing = || Error::NoSuchField(reference.name.to_owned(), selector.to_owned());
        match item.field(selector).ok_or_else(missing)? {
            FieldValue::Plain(v) => Ok(Zeroizing::new(v.as_bytes().to_vec())),
            FieldValue::Otp(secret) => {
                let code = crate::otp::Totp::parse(secret)?.code_at(unix_time);
                Ok(Zeroizing::new(code.into_bytes()))
            }
        }
    }

    /// The item stored under `name`. With `full`, a sensitive item is read
    /// from its sealed secret (needing the sensitive key); without, its
    /// redacted copy is returned unless the key is held.
    fn stored(&self, name: &str, full: bool) -> Result<Option<Stored>> {
        validate_name(name)?;
        let id = self.item_id(name);
        let Some((blob, secret)) = self.row(&id)? else {
            return Ok(None);
        };
        let payload = crypto::open(&self.keys.item, &self.keys.item_aad(&id), &blob)?;
        let (stored_name, stored) = decode_item(&payload)?;
        if stored_name != name {
            return Err(Error::Corrupt(format!(
                "item `{name}` holds a different name"
            )));
        }
        if let Stored::Structured(item) = &stored
            && !self.keys.legacy
            && item.kind.is_sensitive()
        {
            // A card or SSH key must be split; a whole one in the main-key
            // part wasn't written by stash.
            return Err(Error::Corrupt(format!(
                "item `{name}` holds a sensitive item outside its seal"
            )));
        }
        let redacted_kind = match &stored {
            Stored::Redacted(item) => item.kind,
            _ => return Ok(Some(stored)),
        };
        // Only cards, bank accounts, and SSH keys are ever split; a
        // redacted copy claiming another kind wasn't written by stash (and
        // would let an edit save the hidden values under the main key).
        if !redacted_kind.is_sensitive() {
            return Err(Error::Corrupt(format!(
                "item `{name}` has a redacted copy of the wrong kind"
            )));
        }
        let Some(sensitive) = &self.sensitive else {
            return if full {
                Err(Error::SensitiveLocked(name.to_owned()))
            } else {
                Ok(Some(stored))
            };
        };
        let secret =
            secret.ok_or_else(|| Error::Corrupt(format!("item `{name}` lost its secret part")))?;
        let full_payload =
            crypto::open(&sensitive_item_key(sensitive), &sensitive_aad(&id), &secret)?;
        let (secret_name, full_item) = decode_item(&full_payload)?;
        let full_kind = match &full_item {
            Stored::Structured(item) => Some(item.kind),
            _ => None,
        };
        if secret_name != name || full_kind != Some(redacted_kind) {
            return Err(Error::Corrupt(format!(
                "item `{name}` holds a different secret"
            )));
        }
        Ok(Some(full_item))
    }

    /// Delete an item.
    pub fn remove(&mut self, name: &str) -> Result<()> {
        validate_name(name)?;
        if !self.is_current() {
            return Err(self.upgrade_error());
        }
        let id = self.item_id(name);
        let tx = begin_write(&mut self.conn, &self.keys, None)?;
        let deleted = tx.execute("DELETE FROM items WHERE id = ?1", params![id.as_slice()])?;
        if deleted == 0 {
            return Err(Error::NotFound(name.to_owned()));
        }
        bump_mac(&tx, &self.keys)?;
        tx.commit()?;
        Ok(())
    }

    /// All item names, sorted. Values are never returned.
    pub fn names(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT id, blob FROM items")?;
        let mut rows = stmt.query([])?;
        let mut names = Vec::new();
        while let Some(row) = rows.next()? {
            let id: Vec<u8> = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            let payload = crypto::open(&self.keys.item, &self.keys.item_aad(&id), &blob)?;
            names.push(decode_name(&payload)?.to_owned());
        }
        names.sort();
        Ok(names)
    }

    /// One summary per item, sorted by name: kind, username, URL, whether it
    /// has 2FA. No secret values, and no sensitive key needed.
    pub fn summaries(&self) -> Result<Vec<Summary>> {
        let mut stmt = self.conn.prepare("SELECT id, blob FROM items")?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let id: Vec<u8> = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            let payload = crypto::open(&self.keys.item, &self.keys.item_aad(&id), &blob)?;
            let (name, stored) = decode_item(&payload)?;
            out.push(match stored.structured() {
                None => Summary {
                    name,
                    kind: Kind::Secret,
                    username: None,
                    url: None,
                    has_otp: false,
                    updated: 0,
                    subtitle: None,
                },
                Some(item) => Summary {
                    name,
                    kind: item.kind,
                    username: item.username().map(str::to_owned),
                    url: item.url().map(str::to_owned),
                    has_otp: item.has_otp(),
                    updated: item.updated,
                    subtitle: item.subtitle(),
                },
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Replace both keys with new random ones and re-encrypt every item
    /// (and change the master password, if `new_password` is given). An
    /// old copy of the vault, and the old password, then open nothing new.
    /// Needs the current master password.
    pub fn rekey(&mut self, password: &[u8], new_password: Option<&[u8]>) -> Result<()> {
        if !self.is_current() {
            return Err(self.upgrade_error());
        }
        self.unlock_sensitive(password)?;
        let main = crypto::random_key()?;
        let sensitive = crypto::random_key()?;
        let keys = Keys::new(Zeroizing::new(*main), FORMAT_VERSION);
        let wrap_with = new_password.unwrap_or(password);

        // Everything under one write lock, so nothing another process adds
        // in between is lost, and only from a vault that checks out. The
        // safety copy (old keys) is taken under the lock too, and removed
        // on every failure, so it never lingers by accident.
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let backup = sibling_path(&self.path, "rekey-backup");
        let result = (|| {
            verify_key_check(&self.conn, &self.keys).map_err(keys_changed)?;
            verify_mac(&self.conn, &self.keys)?;
            copy_private(&self.path, &backup)?;
            let items = self.all_full()?;
            self.conn.execute("DELETE FROM items", [])?;
            for (name, stored) in &items {
                insert_row(&self.conn, &keys, &sensitive, name, stored)?;
            }
            write_header(
                &self.conn,
                wrap_with,
                strengthen_target(),
                &main,
                &sensitive,
            )?;
            bump_mac(&self.conn, &keys)?;
            self.conn.execute_batch("COMMIT")?;
            Ok(())
        })();
        if let Err(e) = result {
            let _ = self.conn.execute_batch("ROLLBACK");
            let _ = fs::remove_file(&backup);
            return Err(e);
        }
        self.keys = keys;
        self.sensitive = Some(sensitive);
        // Prove it: reopen with the new keys and decrypt everything. Only
        // then does the safety copy go (best effort).
        let check = (|| {
            let mut fresh = Vault::open_with_key(&self.path, &self.keys.main)?;
            fresh.unlock_sensitive_with_key(self.sensitive.as_ref().expect("just set"))?;
            fresh.all_full().map(|_| ())
        })();
        match check {
            Ok(()) => {
                let _ = fs::remove_file(&backup);
                Ok(())
            }
            Err(e) => Err(Error::RekeyUnverified(e.to_string(), backup)),
        }
    }

    /// Every item, fully decrypted (needs the sensitive key).
    fn all_full(&self) -> Result<Vec<(String, Stored)>> {
        let names = self.names()?;
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            let stored = self
                .stored(&name, true)?
                .ok_or_else(|| Error::NotFound(name.clone()))?;
            out.push((name, stored));
        }
        Ok(out)
    }

    fn item_id(&self, name: &str) -> [u8; 32] {
        crypto::hmac(self.keys.index.as_ref(), name.as_bytes())
    }

    fn row(&self, id: &[u8]) -> Result<Option<Row>> {
        let sql = if self.version >= 3 {
            "SELECT blob, secret FROM items WHERE id = ?1"
        } else {
            "SELECT blob, NULL FROM items WHERE id = ?1"
        };
        Ok(self
            .conn
            .query_row(sql, params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?)
    }
}

/// Unwrap the main key (and, in v3, the sensitive key) with the password.
fn unwrap_header(conn: &Connection, version: i64, password: &[u8]) -> Result<Unwrapped> {
    let params = KdfParams {
        m_cost_kib: meta(conn, "kdf_m_cost_kib")?,
        t_cost: meta(conn, "kdf_t_cost")?,
        p_cost: meta(conn, "kdf_p_cost")?,
    };
    check_kdf(params)?;
    let salt: Vec<u8> = meta(conn, "kdf_salt")?;
    let wrapped: Vec<u8> = meta(conn, "wrapped_key")?;
    let kek = crypto::derive_kek(password, &salt, params)?;
    let main = unwrap_key(
        &kek,
        &header_aad(b"stash/vault-key/v1", version, params, &salt),
        &wrapped,
    )?;
    let sensitive = if version >= 3 {
        let wrapped: Vec<u8> = meta(conn, "wrapped_sensitive_key")?;
        Some(unwrap_key(
            &kek,
            &header_aad(b"stash/v3/sensitive-key", version, params, &salt),
            &wrapped,
        )?)
    } else {
        None
    };
    drop(kek);
    Ok(Unwrapped {
        main,
        sensitive,
        params,
    })
}

fn unwrap_key(kek: &SecretKey, aad: &[u8], wrapped: &[u8]) -> Result<SecretKey> {
    let unwrapped = crypto::open(kek, aad, wrapped).map_err(|_| Error::WrongPassword)?;
    if unwrapped.len() != crypto::KEY_LEN {
        return Err(Error::Corrupt("a vault key has the wrong length".into()));
    }
    let mut key = Zeroizing::new([0u8; crypto::KEY_LEN]);
    key.copy_from_slice(&unwrapped);
    Ok(key)
}

/// Write a v3 header: fresh salt, both keys wrapped with the KEK from
/// `password` and `params`, and their check values.
fn write_header(
    tx: &Connection,
    password: &[u8],
    params: KdfParams,
    main: &SecretKey,
    sensitive: &SecretKey,
) -> Result<()> {
    let salt: [u8; SALT_LEN] = crypto::random_bytes()?;
    let kek = crypto::derive_kek(password, &salt, params)?;
    let wrapped_main = crypto::seal(
        &kek,
        &header_aad(b"stash/vault-key/v1", FORMAT_VERSION, params, &salt),
        main.as_ref(),
    )?;
    let wrapped_sensitive = crypto::seal(
        &kek,
        &header_aad(b"stash/v3/sensitive-key", FORMAT_VERSION, params, &salt),
        sensitive.as_ref(),
    )?;
    let keys = Keys::new(Zeroizing::new(**main), FORMAT_VERSION);
    let mut set = tx.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)")?;
    set.execute(params!["format_version", FORMAT_VERSION])?;
    set.execute(params!["kdf_m_cost_kib", params.m_cost_kib])?;
    set.execute(params!["kdf_t_cost", params.t_cost])?;
    set.execute(params!["kdf_p_cost", params.p_cost])?;
    set.execute(params!["kdf_salt", salt.as_slice()])?;
    set.execute(params!["wrapped_key", wrapped_main])?;
    set.execute(params!["wrapped_sensitive_key", wrapped_sensitive])?;
    set.execute(params!["key_check", keys.check().as_slice()])?;
    set.execute(params![
        "sensitive_key_check",
        sensitive_check(sensitive).as_slice()
    ])?;
    Ok(())
}

/// Seal one item into a v3 row.
fn insert_row(
    tx: &Connection,
    keys: &Keys,
    sensitive: &SecretKey,
    name: &str,
    stored: &Stored,
) -> Result<()> {
    let id = crypto::hmac(keys.index.as_ref(), name.as_bytes());
    let (payload, secret) = match stored {
        Stored::Secret(value) => (encode_secret(name, value), None),
        Stored::Structured(item) if item.kind.is_sensitive() => (
            encode_with(&REDACTED, name, &item.redacted())?,
            Some(encode_with(&STRUCTURED, name, item)?),
        ),
        Stored::Structured(item) => (encode_with(&STRUCTURED, name, item)?, None),
        Stored::Redacted(_) => {
            return Err(Error::Corrupt(format!("item `{name}` wasn't fully read")));
        }
    };
    let blob = crypto::seal(&keys.item, &keys.item_aad(&id), &payload)?;
    let secret = match secret {
        Some(s) => Some(crypto::seal(
            &sensitive_item_key(sensitive),
            &sensitive_aad(&id),
            &s,
        )?),
        None => None,
    };
    tx.execute(
        "INSERT INTO items (id, blob, secret) VALUES (?1, ?2, ?3)",
        params![id.as_slice(), blob, secret],
    )?;
    Ok(())
}

/// Upgrade a version 1 or 2 vault to version 3, in one transaction, after
/// copying the file to a backup next to it: new keys, every item
/// re-encrypted (sensitive kinds split), a MAC over the whole vault, and
/// today's KDF settings. Returns the new keys and the backup's path.
fn upgrade(
    conn: &mut Connection,
    path: &Path,
    legacy: &Keys,
    password: &[u8],
) -> Result<Option<(Keys, SecretKey, PathBuf)>> {
    // Everything under one write lock: two stash processes unlocking the
    // old vault at once must not both upgrade it.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = meta(&tx, "format_version")?;
    if version >= FORMAT_VERSION {
        // Someone else just did it.
        return Ok(None);
    }
    // Read everything first, so a damaged item stops the upgrade before
    // anything changes.
    let mut items = Vec::new();
    {
        let mut stmt = tx.prepare("SELECT id, blob FROM items")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let id: Vec<u8> = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            let payload = crypto::open(&legacy.item, &legacy.item_aad(&id), &blob)?;
            items.push(decode_item(&payload)?);
        }
    }
    // The backup, taken while we hold the lock, so it's consistent.
    let backup = sibling_path(path, &format!("v{version}-backup"));
    copy_private(path, &backup).map_err(|e| match e {
        Error::Io(io) if io.kind() == ErrorKind::PermissionDenied => Error::Io(io),
        other => Error::UpgradeFailed(format!("couldn't make the backup copy first ({other})")),
    })?;

    let result = (|| {
        let main = crypto::random_key()?;
        let sensitive = crypto::random_key()?;
        let keys = Keys::new(Zeroizing::new(*main), FORMAT_VERSION);
        tx.execute_batch(
            "DROP TABLE items;
             CREATE TABLE items (id BLOB PRIMARY KEY, blob BLOB NOT NULL, secret BLOB) STRICT;",
        )?;
        for (name, stored) in &items {
            insert_row(&tx, &keys, &sensitive, name, stored)?;
        }
        write_header(&tx, password, strengthen_target(), &main, &sensitive)?;
        bump_mac(&tx, &keys)?;
        tx.commit()?;
        Ok((keys, sensitive))
    })();
    match result {
        Ok((keys, sensitive)) => Ok(Some((keys, sensitive, backup))),
        Err(e) => {
            // Nothing changed; the copy isn't needed.
            let _ = fs::remove_file(&backup);
            Err(e)
        }
    }
}

/// A private (`0600`) byte-for-byte copy of the vault file. Taken while
/// this process holds the write lock, so no write is in progress.
fn copy_private(src: &Path, dest: &Path) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut out = opts.open(dest)?;
    let copied = fs::File::open(src).and_then(|mut input| std::io::copy(&mut input, &mut out));
    if let Err(e) = copied.and_then(|_| out.sync_all()) {
        let _ = fs::remove_file(dest);
        return Err(e.into());
    }
    Ok(())
}

/// `vault.db` → `vault.db.<suffix>` (or with a timestamp if that exists).
fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{suffix}"));
    let candidate = PathBuf::from(&name);
    if !candidate.exists() {
        return candidate;
    }
    name.push(format!("-{}", unix_now()));
    PathBuf::from(name)
}

/// Start a write: take the write lock, then make sure this process's keys
/// still match the file (another stash command may have replaced them) and
/// that the vault is still intact (so a write never re-blesses tampering
/// done since it was opened). Everything after runs in this transaction.
fn begin_write<'a>(
    conn: &'a mut Connection,
    keys: &Keys,
    sensitive: Option<&SecretKey>,
) -> Result<rusqlite::Transaction<'a>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    verify_key_check(&tx, keys).map_err(keys_changed)?;
    if let Some(sensitive) = sensitive {
        verify_sensitive_check(&tx, sensitive).map_err(keys_changed)?;
    }
    verify_mac(&tx, keys)?;
    Ok(tx)
}

/// A key that no longer matches during a write means the keys were
/// replaced since this process unlocked.
fn keys_changed(e: Error) -> Error {
    match e {
        Error::WrongKey => Error::KeysChanged,
        other => other,
    }
}

/// The vault-wide MAC: the write counter and every row's id and the hashes
/// of its two blobs, in id order.
fn compute_mac(conn: &Connection, keys: &Keys, counter: i64) -> Result<[u8; 32]> {
    let mut data = b"stash/v3/vault-mac".to_vec();
    data.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    data.extend_from_slice(&counter.to_le_bytes());
    let mut stmt = conn.prepare("SELECT id, blob, secret FROM items ORDER BY id")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let id: Vec<u8> = row.get(0)?;
        let blob: Vec<u8> = row.get(1)?;
        let secret: Option<Vec<u8>> = row.get(2)?;
        data.extend_from_slice(&(id.len() as u32).to_le_bytes());
        data.extend_from_slice(&id);
        data.extend_from_slice(&Sha256::digest(&blob));
        match secret {
            Some(s) => {
                data.push(1);
                data.extend_from_slice(&Sha256::digest(&s));
            }
            None => data.push(0),
        }
    }
    Ok(crypto::hmac(keys.mac.as_ref(), &data))
}

/// After a change: bump the counter and store the new MAC (same
/// transaction as the change).
fn bump_mac(tx: &Connection, keys: &Keys) -> Result<()> {
    let counter: i64 = tx
        .query_row(
            "SELECT value FROM meta WHERE key = 'write_counter'",
            [],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    let counter = counter + 1;
    let mac = compute_mac(tx, keys, counter)?;
    tx.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('write_counter', ?1)",
        params![counter],
    )?;
    tx.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('vault_mac', ?1)",
        params![mac.as_slice()],
    )?;
    Ok(())
}

fn verify_mac(conn: &Connection, keys: &Keys) -> Result<()> {
    let counter: i64 = meta(conn, "write_counter")?;
    let stored: Vec<u8> = meta(conn, "vault_mac")?;
    let expected = compute_mac(conn, keys, counter)?;
    if crypto::ct_eq(&stored, &expected) {
        Ok(())
    } else {
        Err(Error::Tampered)
    }
}

fn verify_key_check(conn: &Connection, keys: &Keys) -> Result<()> {
    let stored: Option<Vec<u8>> = conn
        .query_row("SELECT value FROM meta WHERE key = 'key_check'", [], |r| {
            r.get(0)
        })
        .optional()?;
    match stored {
        Some(stored) if crypto::ct_eq(&stored, &keys.check()) => Ok(()),
        // Very old vaults have no key check: only a password unlock (which
        // upgrades them) opens those.
        _ => Err(Error::WrongKey),
    }
}

fn verify_sensitive_check(conn: &Connection, sensitive: &SecretKey) -> Result<()> {
    let stored: Vec<u8> = meta(conn, "sensitive_key_check")?;
    if crypto::ct_eq(&stored, &sensitive_check(sensitive)) {
        Ok(())
    } else {
        Err(Error::WrongKey)
    }
}

/// Refuse KDF settings outside sane bounds before running Argon2 on them.
fn check_kdf(params: KdfParams) -> Result<()> {
    let ok = (8..=MAX_KDF.m_cost_kib).contains(&params.m_cost_kib)
        && (1..=MAX_KDF.t_cost).contains(&params.t_cost)
        && (1..=MAX_KDF.p_cost).contains(&params.p_cost);
    if ok {
        Ok(())
    } else {
        Err(Error::Corrupt(
            "the vault header asks for key-derivation settings out of range".into(),
        ))
    }
}

/// What weak KDF settings are raised to on a password unlock.
fn strengthen_target() -> KdfParams {
    if cfg!(test) {
        // Unit tests use fast settings throughout.
        KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    } else {
        KdfParams::default()
    }
}

/// Less total work than `target` (memory × passes), or less memory than
/// half of it. Stronger custom settings are left alone.
fn weaker_than(params: KdfParams, target: KdfParams) -> bool {
    let work = |p: KdfParams| u64::from(p.m_cost_kib) * u64::from(p.t_cost);
    work(params) < work(target) || params.m_cost_kib < target.m_cost_kib / 2
}

/// `Ok(None)` if the write failed only because the vault is read-only or
/// another process holds it; other errors pass through.
fn tolerate_unwritable<T>(result: Result<T>) -> Result<Option<T>> {
    use rusqlite::ErrorCode::{CannotOpen, DatabaseBusy, DatabaseLocked, ReadOnly};
    match result {
        Ok(v) => Ok(Some(v)),
        Err(Error::Database(rusqlite::Error::SqliteFailure(e, _)))
            if matches!(
                e.code,
                ReadOnly | DatabaseBusy | DatabaseLocked | CannotOpen
            ) =>
        {
            Ok(None)
        }
        Err(Error::Io(e)) if e.kind() == ErrorKind::PermissionDenied => Ok(None),
        Err(e) => Err(e),
    }
}

fn connect(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // Wait briefly for another stash process instead of failing at once.
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    // Overwrite deleted rows with zeros instead of leaving them in free pages.
    conn.execute_batch("PRAGMA secure_delete = ON;")?;
    Ok(conn)
}

/// Open an existing vault file and check its format version.
fn connect_existing(path: &Path) -> Result<(Connection, i64)> {
    if !path.exists() {
        return Err(Error::VaultMissing(path.to_owned()));
    }
    let conn = connect(path)?;
    let version: i64 = meta(&conn, "format_version")?;
    if !(OLDEST_SUPPORTED_VERSION..=FORMAT_VERSION).contains(&version) {
        return Err(Error::UnsupportedVersion(version));
    }
    Ok((conn, version))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn meta<T: rusqlite::types::FromSql>(conn: &Connection, key: &str) -> Result<T> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()?
        .ok_or_else(|| Error::Corrupt(format!("missing `{key}` in vault header")))
}

fn create_private_dir(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)?;
    Ok(())
}

/// AAD for a wrapped key: binds it to which key it is, the format version,
/// the KDF parameters, and the salt, so none can be swapped undetected.
fn header_aad(label: &[u8], version: i64, params: KdfParams, salt: &[u8]) -> Vec<u8> {
    let mut aad = label.to_vec();
    aad.extend_from_slice(&version.to_le_bytes());
    aad.extend_from_slice(&params.m_cost_kib.to_le_bytes());
    aad.extend_from_slice(&params.t_cost.to_le_bytes());
    aad.extend_from_slice(&params.p_cost.to_le_bytes());
    aad.extend_from_slice(salt);
    aad
}

/// A decrypted item, in whichever encoding it was stored.
enum Stored {
    Secret(Zeroizing<Vec<u8>>),
    Structured(Item),
    /// A sensitive item's redacted copy.
    Redacted(Item),
}

impl Stored {
    fn structured(&self) -> Option<&Item> {
        match self {
            Stored::Structured(item) | Stored::Redacted(item) => Some(item),
            Stored::Secret(_) => None,
        }
    }
}

fn name_header(name: &str) -> [u8; 2] {
    u16::try_from(name.len())
        .expect("names are validated to be short")
        .to_le_bytes()
}

/// `u16 name length (LE) || name || value`.
fn encode_secret(name: &str, value: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(2 + name.len() + value.len()));
    out.extend_from_slice(&name_header(name));
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(value);
    out
}

/// `marker || u16 name length (LE) || name || JSON`.
fn encode_with(marker: &[u8; 2], name: &str, item: &Item) -> Result<Zeroizing<Vec<u8>>> {
    // Size the buffer up front so it never reallocates, which would leave
    // un-wiped copies of the JSON behind.
    let estimate = 256
        + item.notes.len() * 6
        + item.summary.as_ref().map_or(0, |s| s.len() * 6)
        + item
            .fields
            .iter()
            .map(|f| 64 + (f.label.len() + f.value.len()) * 6)
            .sum::<usize>();
    let mut json = Zeroizing::new(Vec::with_capacity(estimate));
    serde_json::to_writer(&mut *json, item)
        .map_err(|e| Error::Corrupt(format!("encoding item: {e}")))?;
    let mut out = Zeroizing::new(Vec::with_capacity(4 + name.len() + json.len()));
    out.extend_from_slice(marker);
    out.extend_from_slice(&name_header(name));
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/// Just the name, without parsing the contents.
fn decode_name(payload: &[u8]) -> Result<&str> {
    let corrupt = || Error::Corrupt("malformed item".into());
    let payload = payload
        .strip_prefix(&STRUCTURED)
        .or_else(|| payload.strip_prefix(&REDACTED))
        .unwrap_or(payload);
    let (len, rest) = payload.split_first_chunk::<2>().ok_or_else(corrupt)?;
    let len = usize::from(u16::from_le_bytes(*len));
    let name = rest.get(..len).ok_or_else(corrupt)?;
    std::str::from_utf8(name).map_err(|_| corrupt())
}

fn decode_item(payload: &[u8]) -> Result<(String, Stored)> {
    let corrupt = || Error::Corrupt("malformed item".into());
    enum Encoding {
        Secret,
        Structured,
        Redacted,
    }
    let (encoding, payload) = if let Some(rest) = payload.strip_prefix(&STRUCTURED) {
        (Encoding::Structured, rest)
    } else if let Some(rest) = payload.strip_prefix(&REDACTED) {
        (Encoding::Redacted, rest)
    } else {
        (Encoding::Secret, payload)
    };
    let (len, rest) = payload.split_first_chunk::<2>().ok_or_else(corrupt)?;
    let len = usize::from(u16::from_le_bytes(*len));
    if rest.len() < len {
        return Err(corrupt());
    }
    let (name, body) = rest.split_at(len);
    let name = std::str::from_utf8(name).map_err(|_| corrupt())?.to_owned();
    let parse = |body: &[u8]| -> Result<Item> {
        serde_json::from_slice(body).map_err(|e| Error::Corrupt(format!("item `{name}`: {e}")))
    };
    let stored = match encoding {
        Encoding::Structured => Stored::Structured(parse(body)?),
        Encoding::Redacted => Stored::Redacted(parse(body)?),
        Encoding::Secret => Stored::Secret(Zeroizing::new(body.to_vec())),
    };
    Ok((name, stored))
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;
    use tempfile::TempDir;

    use super::*;

    /// Minimum Argon2 cost so tests run fast. Never use outside tests.
    const FAST: KdfParams = KdfParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    fn new_vault() -> (TempDir, PathBuf, Vault) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sub/vault.db");
        let vault = Vault::create(&path, b"correct horse", FAST).unwrap();
        (dir, path, vault)
    }

    fn value(vault: &Vault, name: &str) -> Vec<u8> {
        vault.get(name).unwrap().expose_secret().to_vec()
    }

    #[test]
    fn the_audit_key_is_published_and_trust_tags_belong_to_one_vault() {
        let (dir, path, vault) = new_vault();
        let secret = vault.audit_secret().unwrap();
        let public = crypto::x25519_public(&secret);
        assert_eq!(Vault::audit_public_key(&path).unwrap(), Some(public));

        // A replaced public key is put back by the next unlock.
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'audit_public_key'",
            [[7u8; 32].as_slice()],
        )
        .unwrap();
        let reopened = Vault::open_with_key(&path, vault.key()).unwrap();
        assert_eq!(Vault::audit_public_key(&path).unwrap(), Some(public));

        assert_eq!(
            vault.trust_tag(b"x").unwrap(),
            reopened.trust_tag(b"x").unwrap()
        );
        assert_ne!(
            vault.trust_tag(b"x").unwrap(),
            vault.trust_tag(b"y").unwrap()
        );
        let other = Vault::create(&dir.path().join("other.db"), b"password", FAST).unwrap();
        assert_ne!(
            vault.trust_tag(b"x").unwrap(),
            other.trust_tag(b"x").unwrap()
        );
        assert!(Vault::audit_public_key(&dir.path().join("missing.db")).is_err());
    }

    #[test]
    fn add_get_list_remove() {
        let (_dir, _path, mut vault) = new_vault();
        vault.add("github/token", b"ghp_123", false).unwrap();
        vault.add("aws/key", b"AKIA", false).unwrap();

        assert_eq!(value(&vault, "github/token"), b"ghp_123");
        assert_eq!(vault.names().unwrap(), ["aws/key", "github/token"]);

        vault.remove("aws/key").unwrap();
        assert_eq!(vault.names().unwrap(), ["github/token"]);
        assert!(matches!(vault.get("aws/key"), Err(Error::NotFound(_))));
        assert!(matches!(vault.remove("aws/key"), Err(Error::NotFound(_))));
    }

    #[test]
    fn add_refuses_duplicates_unless_overwriting() {
        let (_dir, _path, mut vault) = new_vault();
        vault.add("k", b"one", false).unwrap();
        assert!(matches!(
            vault.add("k", b"two", false),
            Err(Error::AlreadyExists(_))
        ));
        assert_eq!(value(&vault, "k"), b"one");
        vault.add("k", b"two", true).unwrap();
        assert_eq!(value(&vault, "k"), b"two");
    }

    #[test]
    fn rejects_invalid_names() {
        let (_dir, _path, mut vault) = new_vault();
        assert!(matches!(
            vault.add("../x", b"v", false),
            Err(Error::InvalidName(..))
        ));
    }

    #[test]
    fn reopens_with_correct_password_only() {
        let (_dir, path, mut vault) = new_vault();
        vault.add("k", b"v", false).unwrap();
        drop(vault);

        assert!(matches!(
            Vault::open(&path, b"wrong"),
            Err(Error::WrongPassword)
        ));
        let vault = Vault::open(&path, b"correct horse").unwrap();
        assert_eq!(value(&vault, "k"), b"v");
    }

    #[test]
    fn create_refuses_to_overwrite_and_open_requires_vault() {
        let (dir, path, _vault) = new_vault();
        assert!(matches!(
            Vault::create(&path, b"x", FAST),
            Err(Error::VaultExists(_))
        ));
        let missing = dir.path().join("missing.db");
        assert!(matches!(
            Vault::open(&missing, b"x"),
            Err(Error::VaultMissing(_))
        ));
    }

    #[test]
    fn names_and_values_are_not_stored_in_plaintext() {
        let (_dir, path, mut vault) = new_vault();
        vault
            .add("very-distinctive-name", b"super-secret-value", false)
            .unwrap();
        drop(vault);
        let raw = fs::read(&path).unwrap();
        let contains = |needle: &[u8]| raw.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(b"very-distinctive-name"));
        assert!(!contains(b"super-secret-value"));
    }

    #[test]
    fn swapping_blobs_between_rows_is_detected() {
        let (_dir, _path, mut vault) = new_vault();
        vault.add("a", b"1", false).unwrap();
        vault.add("b", b"2", false).unwrap();
        let (id_a, id_b) = (vault.item_id("a"), vault.item_id("b"));
        vault
            .conn
            .execute(
                "UPDATE items SET blob = (SELECT blob FROM items WHERE id = ?2) WHERE id = ?1",
                params![id_a.as_slice(), id_b.as_slice()],
            )
            .unwrap();
        assert!(matches!(vault.get("a"), Err(Error::Decrypt)));
    }

    #[test]
    fn tampered_kdf_params_are_detected() {
        let (_dir, path, vault) = new_vault();
        drop(vault);
        let conn = Connection::open(&path).unwrap();
        conn.execute("UPDATE meta SET value = 2 WHERE key = 'kdf_t_cost'", [])
            .unwrap();
        drop(conn);
        assert!(matches!(
            Vault::open(&path, b"correct horse"),
            Err(Error::WrongPassword)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn vault_file_and_new_dirs_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path, _vault) = new_vault();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[test]
    fn binary_values_round_trip() {
        let (_dir, _path, mut vault) = new_vault();
        let bytes: Vec<u8> = (0..=255).collect();
        vault.add("bin", &bytes, false).unwrap();
        assert_eq!(value(&vault, "bin"), bytes);
    }

    #[test]
    fn open_with_key_accepts_only_the_right_key() {
        let (_dir, path, mut vault) = new_vault();
        vault.add("k", b"v", false).unwrap();
        let key = *vault.key();
        drop(vault);

        let vault = Vault::open_with_key(&path, &key).unwrap();
        assert_eq!(value(&vault, "k"), b"v");
        let wrong = [7u8; crypto::KEY_LEN];
        assert!(matches!(
            Vault::open_with_key(&path, &wrong),
            Err(Error::WrongKey)
        ));
    }

    fn github_login() -> Item {
        let mut item = Item::login(Some("octocat"), "hunter2!", Some("https://github.com"));
        item.set(
            crate::item::ONE_TIME_PASSWORD,
            crate::FieldKind::Otp,
            "JBSWY3DPEHPK3PXP",
        );
        item
    }

    #[test]
    fn stores_and_resolves_structured_items() {
        let (_dir, path, mut vault) = new_vault();
        vault.put("github", &github_login(), false).unwrap();
        vault
            .put("notes/wifi", &Item::note("ssid: home"), false)
            .unwrap();
        drop(vault);
        let vault = Vault::open(&path, b"correct horse").unwrap();

        // Main values.
        assert_eq!(value(&vault, "github"), b"hunter2!");
        assert_eq!(value(&vault, "notes/wifi"), b"ssid: home");

        // Field references, including the current 2FA code.
        let resolve = |s: &str| {
            let r = crate::reference::parse(s).unwrap().unwrap();
            String::from_utf8(vault.resolve(&r, 59).unwrap().to_vec()).unwrap()
        };
        assert_eq!(resolve("stash://github#username"), "octocat");
        assert_eq!(resolve("stash://github#url"), "https://github.com");
        let expected = crate::otp::Totp::parse("JBSWY3DPEHPK3PXP")
            .unwrap()
            .code_at(59);
        assert_eq!(resolve("stash://github#otp"), expected);
        let missing = crate::reference::parse("stash://github#nope")
            .unwrap()
            .unwrap();
        assert!(matches!(
            vault.resolve(&missing, 0),
            Err(Error::NoSuchField(..))
        ));

        let item = vault.item("github").unwrap();
        assert_eq!(item.kind, Kind::Login);
        assert!(item.created > 0 && item.updated >= item.created);
    }

    #[test]
    fn summaries_describe_items_without_values() {
        let (_dir, _path, mut vault) = new_vault();
        vault.put("github", &github_login(), false).unwrap();
        vault.add("api/key", b"tok", false).unwrap();
        let s = vault.summaries().unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].name.as_str(), s[0].kind), ("api/key", Kind::Secret));
        assert_eq!(s[1].username.as_deref(), Some("octocat"));
        assert_eq!(s[1].url.as_deref(), Some("https://github.com"));
        assert!(s[1].has_otp);
        assert_eq!(vault.names().unwrap(), ["api/key", "github"]);
    }

    #[test]
    fn plain_secrets_read_as_secret_items_and_binary_ones_refuse() {
        let (_dir, _path, mut vault) = new_vault();
        vault.add("tok", b"abc", false).unwrap();
        vault.add("bin", &[0xff, 0x00], false).unwrap();
        let item = vault.item("tok").unwrap();
        assert_eq!((item.kind, item.primary()), (Kind::Secret, Some("abc")));
        assert!(matches!(vault.item("bin"), Err(Error::NotText(_))));
        // Putting a secret item keeps the original encoding.
        vault.put("tok2", &Item::secret("xyz"), false).unwrap();
        assert_eq!(value(&vault, "tok2"), b"xyz");
    }

    #[test]
    fn editing_keeps_the_creation_time_but_replacing_resets_it() {
        let (_dir, _path, mut vault) = new_vault();
        let mut original = github_login();
        original.created = 1_000;
        vault.put("github", &original, false).unwrap();

        let mut edited = vault.item("github").unwrap();
        edited.set("password", crate::FieldKind::Concealed, "new!");
        vault.put("github", &edited, true).unwrap();
        let after = vault.item("github").unwrap();
        assert_eq!(after.created, 1_000);
        assert_eq!(after.primary(), Some("new!"));

        // A brand-new item put over the old one (`add --force`) is new.
        vault.put("github", &github_login(), true).unwrap();
        assert!(vault.item("github").unwrap().created > 1_000);
    }

    #[test]
    fn secrets_with_notes_or_extra_fields_are_not_truncated() {
        // Regression: these used to be saved as plain secrets, silently
        // dropping the notes and extra fields.
        let (_dir, _path, mut vault) = new_vault();
        let mut item = Item::secret("tok");
        item.notes = "rotate every 90 days".into();
        item.set("scope", crate::FieldKind::Text, "read-only");
        vault.put("api/key", &item, false).unwrap();
        let back = vault.item("api/key").unwrap();
        assert_eq!(back.kind, Kind::Secret);
        assert_eq!(back.notes, "rotate every 90 days");
        assert_eq!(back.labeled("scope").unwrap().value, "read-only");
        assert_eq!(value(&vault, "api/key"), b"tok");
    }

    /// Rewrite the header exactly as v0.1–v0.5 wrote it.
    #[test]
    fn only_read_only_and_busy_errors_are_tolerated() {
        use rusqlite::ffi;
        let failure = |code| {
            Err::<(), _>(Error::Database(rusqlite::Error::SqliteFailure(
                ffi::Error::new(code),
                None,
            )))
        };
        for code in [ffi::SQLITE_READONLY, ffi::SQLITE_BUSY, ffi::SQLITE_LOCKED] {
            assert!(
                matches!(tolerate_unwritable(failure(code)), Ok(None)),
                "{code}"
            );
        }
        for code in [ffi::SQLITE_CORRUPT, ffi::SQLITE_FULL, ffi::SQLITE_IOERR] {
            assert!(tolerate_unwritable(failure(code)).is_err(), "{code}");
        }
        assert!(tolerate_unwritable(Err::<(), _>(Error::Decrypt)).is_err());
        assert!(matches!(tolerate_unwritable(Ok(5)), Ok(Some(5))));
    }

    #[test]
    fn rejects_vaults_from_the_future() {
        let (_dir, path, vault) = new_vault();
        vault
            .conn
            .execute("UPDATE meta SET value = 4 WHERE key = 'format_version'", [])
            .unwrap();
        drop(vault);
        assert!(matches!(
            Vault::open(&path, b"correct horse"),
            Err(Error::UnsupportedVersion(4))
        ));
    }

    #[test]
    fn structured_items_are_encrypted_too() {
        let (_dir, path, mut vault) = new_vault();
        vault.put("github", &github_login(), false).unwrap();
        drop(vault);
        let raw = fs::read(&path).unwrap();
        for needle in [&b"octocat"[..], b"hunter2!", b"login", b"JBSWY3DP"] {
            assert!(!raw.windows(needle.len()).any(|w| w == needle));
        }
    }

    #[test]
    fn cards_are_validated_on_every_save_and_summarized_safely() {
        let (_dir, path, mut vault) = new_vault();
        let card = Item::card(&crate::item::CardDetails {
            number: "5555 5555 5555 4444",
            expiry: Some("01/30"),
            cvv: Some("321"),
            ..Default::default()
        })
        .unwrap();
        vault.put("cards/work", &card, false).unwrap();
        let s = &vault.summaries().unwrap()[0];
        assert_eq!(s.kind, Kind::Card);
        assert_eq!(s.subtitle.as_deref(), Some("Mastercard •••• 4444 · 01/30"));
        assert_eq!(value(&vault, "cards/work"), b"5555555555554444");

        // Edits are normalized like new items...
        let mut spaced = vault.item("cards/work").unwrap();
        spaced.set(
            crate::item::CARD_NUMBER,
            crate::FieldKind::Concealed,
            "4242 4242 4242 4242",
        );
        spaced.set(crate::item::EXPIRY, crate::FieldKind::Text, "3/2031");
        vault.put("cards/work", &spaced, true).unwrap();
        let saved = vault.item("cards/work").unwrap();
        assert_eq!(saved.primary(), Some("4242424242424242"));
        assert_eq!(saved.labeled(crate::item::EXPIRY).unwrap().value, "03/31");

        // ...and an edit that breaks the number is refused, whoever makes it.
        let mut broken = vault.item("cards/work").unwrap();
        broken.set(
            crate::item::CARD_NUMBER,
            crate::FieldKind::Concealed,
            "5555555555554445",
        );
        assert!(matches!(
            vault.put("cards/work", &broken, true),
            Err(Error::InvalidPayment(_))
        ));
        drop(vault);
        let raw = fs::read(&path).unwrap();
        assert!(
            !raw.windows(16).any(|w| w == b"5555555555554444"),
            "card numbers are encrypted"
        );
    }

    // ---- Version 3: the sensitive key, the vault MAC, upgrades, rekeying ----

    fn visa() -> Item {
        let mut card = Item::card(&crate::item::CardDetails {
            cardholder: Some("J Lopez"),
            number: "4242 4242 4242 4242",
            expiry: Some("08/27"),
            cvv: Some("123"),
            pin: Some("9876"),
            billing_zip: Some("78666"),
        })
        .unwrap();
        card.notes = "the blue one".into();
        card
    }

    #[test]
    fn sensitive_items_need_the_sensitive_key_every_time() {
        let (_dir, path, mut vault) = new_vault();
        vault.put("cards/visa", &visa(), false).unwrap();
        vault.put("github", &github_login(), false).unwrap();
        let main = *vault.key();
        let sensitive = *vault.sensitive_key().unwrap();
        drop(vault);

        // What a session holds: everything but sensitive values.
        let mut session = Vault::open_with_key(&path, &main).unwrap();
        assert!(!session.has_sensitive());
        assert_eq!(
            session
                .item("github")
                .unwrap()
                .labeled("password")
                .unwrap()
                .value,
            "hunter2!"
        );
        assert!(matches!(
            session.item("cards/visa"),
            Err(Error::SensitiveLocked(_))
        ));
        assert!(matches!(
            session.get("cards/visa"),
            Err(Error::SensitiveLocked(_))
        ));
        let reference = crate::reference::parse("stash://cards/visa#cvv")
            .unwrap()
            .unwrap();
        assert!(matches!(
            session.resolve(&reference, 0),
            Err(Error::SensitiveLocked(_))
        ));
        // Lists and the redacted view still work, with no secret in them.
        let summaries = session.summaries().unwrap();
        let card = summaries.iter().find(|s| s.name == "cards/visa").unwrap();
        assert_eq!(card.subtitle.as_deref(), Some("Visa •••• 4242 · 08/27"));
        let redacted = session.item_redacted("cards/visa").unwrap();
        assert!(redacted.is_redacted());
        assert_eq!(redacted.labeled("cardholder").unwrap().value, "J Lopez");
        for label in ["number", "cvv", "pin"] {
            assert_eq!(redacted.labeled(label).unwrap().value, "", "{label}");
        }
        assert_eq!(redacted.notes, "");
        // Writing one needs the key too.
        assert!(matches!(
            session.put("cards/other", &visa(), false),
            Err(Error::SensitiveLocked(_))
        ));

        // With the sensitive key (Touch ID), it reads; then it's forgotten.
        assert!(matches!(
            session.unlock_sensitive_with_key(&[9u8; 32]),
            Err(Error::WrongKey)
        ));
        session.unlock_sensitive_with_key(&sensitive).unwrap();
        let full = session.item("cards/visa").unwrap();
        assert_eq!(full.labeled("cvv").unwrap().value, "123");
        assert_eq!(full.notes, "the blue one");
        session.lock_sensitive();
        assert!(matches!(
            session.item("cards/visa"),
            Err(Error::SensitiveLocked(_))
        ));
        // Or with the master password.
        session.unlock_sensitive(b"correct horse").unwrap();
        assert_eq!(
            session
                .item("cards/visa")
                .unwrap()
                .labeled("pin")
                .unwrap()
                .value,
            "9876"
        );
        session.lock_sensitive();
        assert!(matches!(
            session.unlock_sensitive(b"wrong"),
            Err(Error::WrongPassword)
        ));
    }

    #[test]
    fn sensitive_values_never_leave_the_sensitive_seal() {
        let (_dir, path, mut vault) = new_vault();
        vault.put("cards/visa", &visa(), false).unwrap();
        let id = vault.item_id("cards/visa");
        drop(vault);
        let conn = Connection::open(&path).unwrap();
        let (blob, secret): (Vec<u8>, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT blob, secret FROM items WHERE id = ?1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        // The redacted copy is far smaller than the full item: the values
        // aren't in it at all, encrypted or not.
        assert!(secret.is_some());
        let raw = fs::read(&path).unwrap();
        let contains = |needle: &[u8]| raw.windows(needle.len()).any(|w| w == needle);
        for plain in [&b"4242424242424242"[..], b"J Lopez", b"the blue one"] {
            assert!(!contains(plain));
        }
        assert!(!blob.is_empty());
    }

    #[test]
    fn removing_adding_or_rolling_back_items_is_detected() {
        let (dir, path, mut vault) = new_vault();
        vault.add("api/token", b"original", false).unwrap();
        vault.put("cards/visa", &visa(), false).unwrap();
        let snapshot = dir.path().join("snapshot.db");
        drop(vault);
        fs::copy(&path, &snapshot).unwrap();
        let mut vault = Vault::open(&path, b"correct horse").unwrap();
        vault.add("api/token", b"rotated", true).unwrap();
        vault.remove("cards/visa").unwrap();
        let main = *vault.key();
        drop(vault);

        let tamper = |sql: &str| {
            let copy = dir.path().join("tampered.db");
            fs::copy(&path, &copy).unwrap();
            let conn = Connection::open(&copy).unwrap();
            conn.execute(&format!("ATTACH '{}' AS old", snapshot.display()), [])
                .unwrap();
            conn.execute_batch(sql).unwrap();
            drop(conn);
            copy
        };
        // Put the old token back.
        let rolled_back = tamper(
            "UPDATE items SET blob = (SELECT blob FROM old.items o WHERE o.id = items.id) \
             WHERE id IN (SELECT id FROM old.items)",
        );
        // Bring the deleted card back.
        let resurrected = tamper(
            "INSERT INTO items SELECT * FROM old.items WHERE id NOT IN (SELECT id FROM items)",
        );
        // Silently drop an item.
        let deleted = tamper("DELETE FROM items");
        for copy in [rolled_back, resurrected, deleted] {
            assert!(
                matches!(Vault::open(&copy, b"correct horse"), Err(Error::Tampered)),
                "{}",
                copy.display()
            );
            assert!(matches!(
                Vault::open_with_key(&copy, &main),
                Err(Error::Tampered)
            ));
        }
        // The untouched vault opens.
        assert!(Vault::open_with_key(&path, &main).is_ok());
    }

    #[test]
    fn swapped_blobs_are_also_caught_on_open() {
        let (_dir, path, mut vault) = new_vault();
        vault.add("a", b"1", false).unwrap();
        vault.add("b", b"2", false).unwrap();
        let (id_a, id_b) = (vault.item_id("a"), vault.item_id("b"));
        vault
            .conn
            .execute(
                "UPDATE items SET blob = (SELECT blob FROM items WHERE id = ?2) WHERE id = ?1",
                params![id_a.as_slice(), id_b.as_slice()],
            )
            .unwrap();
        drop(vault);
        assert!(matches!(
            Vault::open(&path, b"correct horse"),
            Err(Error::Tampered)
        ));
    }

    #[test]
    fn absurd_kdf_settings_are_refused_before_running_argon2() {
        let (_dir, path, vault) = new_vault();
        drop(vault);
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE meta SET value = 4294967295 WHERE key = 'kdf_m_cost_kib'",
            [],
        )
        .unwrap();
        drop(conn);
        let started = std::time::Instant::now();
        let err = Vault::open(&path, b"correct horse").err().unwrap();
        assert!(err.to_string().contains("out of range"), "{err}");
        assert!(started.elapsed().as_secs() < 2);
        assert!(
            Vault::create(
                &path.with_file_name("x.db"),
                b"pw",
                KdfParams {
                    m_cost_kib: 1,
                    t_cost: 1,
                    p_cost: 1
                }
            )
            .is_err()
        );
    }

    #[test]
    fn weak_kdf_settings_are_detected_for_strengthening() {
        assert!(weaker_than(FAST, KdfParams::default()));
        assert!(!weaker_than(KdfParams::default(), KdfParams::default()));
        let stronger = KdfParams {
            m_cost_kib: 1 << 20,
            ..KdfParams::default()
        };
        assert!(!weaker_than(stronger, KdfParams::default()));
    }

    /// A vault in the old one-key format (version 1 or 2), as earlier
    /// versions of stash wrote it.
    fn legacy_vault(dir: &TempDir, version: i64) -> (PathBuf, SecretKey) {
        let path = dir.path().join(format!("v{version}.db"));
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta  (key TEXT PRIMARY KEY, value ANY NOT NULL) STRICT;
             CREATE TABLE items (id BLOB PRIMARY KEY, blob BLOB NOT NULL) STRICT;",
        )
        .unwrap();
        let salt: [u8; SALT_LEN] = crypto::random_bytes().unwrap();
        let kek = crypto::derive_kek(b"correct horse", &salt, FAST).unwrap();
        let main = crypto::random_key().unwrap();
        let wrapped = crypto::seal(
            &kek,
            &header_aad(b"stash/vault-key/v1", version, FAST, &salt),
            main.as_ref(),
        )
        .unwrap();
        let keys = Keys::new(Zeroizing::new(*main), version);
        for (k, v) in [
            ("format_version", rusqlite::types::Value::Integer(version)),
            (
                "kdf_m_cost_kib",
                rusqlite::types::Value::Integer(FAST.m_cost_kib.into()),
            ),
            (
                "kdf_t_cost",
                rusqlite::types::Value::Integer(FAST.t_cost.into()),
            ),
            (
                "kdf_p_cost",
                rusqlite::types::Value::Integer(FAST.p_cost.into()),
            ),
            ("kdf_salt", rusqlite::types::Value::Blob(salt.to_vec())),
            ("wrapped_key", rusqlite::types::Value::Blob(wrapped)),
            (
                "key_check",
                rusqlite::types::Value::Blob(keys.check().to_vec()),
            ),
        ] {
            conn.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                params![k, v],
            )
            .unwrap();
        }
        let mut rows: Vec<(String, Zeroizing<Vec<u8>>)> = vec![(
            "api/token".into(),
            encode_secret("api/token", b"ghp_legacy"),
        )];
        if version >= 2 {
            rows.push((
                "github".into(),
                encode_with(&STRUCTURED, "github", &github_login()).unwrap(),
            ));
            rows.push((
                "cards/visa".into(),
                encode_with(&STRUCTURED, "cards/visa", &visa()).unwrap(),
            ));
        }
        for (name, payload) in rows {
            let id = crypto::hmac(keys.index.as_ref(), name.as_bytes());
            let blob = crypto::seal(&keys.item, &keys.item_aad(&id), &payload).unwrap();
            conn.execute(
                "INSERT INTO items (id, blob) VALUES (?1, ?2)",
                params![id.as_slice(), blob],
            )
            .unwrap();
        }
        (path, main)
    }

    #[test]
    fn old_vaults_read_with_their_key_but_change_only_after_upgrading() {
        let dir = TempDir::new().unwrap();
        let (path, old_key) = legacy_vault(&dir, 2);
        let mut by_key = Vault::open_with_key(&path, &old_key).unwrap();
        assert!(!by_key.is_current());
        assert_eq!(value(&by_key, "api/token"), b"ghp_legacy");
        assert_eq!(
            by_key
                .item("cards/visa")
                .unwrap()
                .labeled("cvv")
                .unwrap()
                .value,
            "123"
        );
        assert!(matches!(
            by_key.add("x", b"y", false),
            Err(Error::NeedsUpgrade)
        ));
        assert!(matches!(
            by_key.remove("api/token"),
            Err(Error::NeedsUpgrade)
        ));
    }

    #[test]
    fn a_password_unlock_upgrades_old_vaults_after_a_backup() {
        for version in [1, 2] {
            let dir = TempDir::new().unwrap();
            let (path, old_key) = legacy_vault(&dir, version);
            let vault = Vault::open(&path, b"correct horse").unwrap();
            assert!(vault.is_current(), "v{version}");
            let backup = vault.upgrade_backup().unwrap().to_owned();
            assert_eq!(
                backup,
                dir.path().join(format!("v{version}.db.v{version}-backup"))
            );
            assert_eq!(value(&vault, "api/token"), b"ghp_legacy");
            let main = *vault.key();
            drop(vault);

            // The backup is the old vault, untouched, and private.
            assert_eq!(
                Vault::open_with_key(&backup, &old_key).unwrap().version,
                version
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            // The upgraded vault has new keys: the old one no longer opens it.
            assert!(matches!(
                Vault::open_with_key(&path, &old_key),
                Err(Error::WrongKey)
            ));
            let session = Vault::open_with_key(&path, &main).unwrap();
            assert_eq!(session.version, FORMAT_VERSION);
            if version >= 2 {
                assert_eq!(
                    session
                        .item("github")
                        .unwrap()
                        .labeled("password")
                        .unwrap()
                        .value,
                    "hunter2!"
                );
                // The card moved under the sensitive key.
                assert!(matches!(
                    session.item("cards/visa"),
                    Err(Error::SensitiveLocked(_))
                ));
                let full = Vault::open(&path, b"correct horse").unwrap();
                assert_eq!(
                    full.item("cards/visa")
                        .unwrap()
                        .labeled("cvv")
                        .unwrap()
                        .value,
                    "123"
                );
            }
            // A second unlock doesn't upgrade or back up again.
            let again = Vault::open(&path, b"correct horse").unwrap();
            assert!(again.upgrade_backup().is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_read_only_old_vault_opens_without_upgrading() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let (path, _) = legacy_vault(&dir, 2);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let result = Vault::open(&path, b"correct horse");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut vault = result.unwrap();
        assert!(!vault.is_current());
        assert_eq!(value(&vault, "api/token"), b"ghp_legacy");
        assert!(matches!(
            vault.add("x", b"y", false),
            Err(Error::UpgradeBlocked)
        ));
    }

    #[test]
    fn rekeying_replaces_both_keys_and_can_change_the_password() {
        let (dir, path, mut vault) = new_vault();
        vault.put("cards/visa", &visa(), false).unwrap();
        vault.add("api/token", b"t", false).unwrap();
        let old_main = *vault.key();
        let old_sensitive = *vault.sensitive_key().unwrap();
        let old_copy = dir.path().join("old.db");
        fs::copy(&path, &old_copy).unwrap();

        assert!(matches!(
            vault.rekey(b"wrong", None),
            Err(Error::WrongPassword)
        ));
        vault
            .rekey(b"correct horse", Some(b"new password"))
            .unwrap();
        assert_ne!(vault.key(), &old_main);
        assert_ne!(vault.sensitive_key().unwrap(), &old_sensitive);
        assert_eq!(
            vault
                .item("cards/visa")
                .unwrap()
                .labeled("cvv")
                .unwrap()
                .value,
            "123"
        );
        drop(vault);

        assert!(matches!(
            Vault::open(&path, b"correct horse"),
            Err(Error::WrongPassword)
        ));
        let vault = Vault::open(&path, b"new password").unwrap();
        assert_eq!(value(&vault, "api/token"), b"t");
        assert!(matches!(
            Vault::open_with_key(&path, &old_main),
            Err(Error::WrongKey)
        ));
        // The old copy, with the old password, can't read the new vault.
        let old = Vault::open(&old_copy, b"correct horse").unwrap();
        assert_ne!(old.key(), vault.key());
    }

    #[test]
    fn a_process_with_replaced_keys_cant_write_and_break_the_vault() {
        let (_dir, path, mut vault) = new_vault();
        vault.add("api/token", b"t", false).unwrap();
        // The Mac app, say, unlocked earlier with today's main key...
        let mut stale = Vault::open_with_key(&path, vault.key()).unwrap();
        // ...then `stash rekey` (or `passwd`) runs in a terminal.
        vault.rekey(b"correct horse", None).unwrap();
        // The app's next save is refused instead of corrupting the vault.
        assert!(matches!(
            stale.add("note", b"x", false),
            Err(Error::KeysChanged)
        ));
        assert!(matches!(stale.remove("api/token"), Err(Error::KeysChanged)));
        drop(vault);
        let reopened = Vault::open(&path, b"correct horse").unwrap();
        assert_eq!(value(&reopened, "api/token"), b"t");
        // No safety copy is left behind once the rekey checked out.
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("rekey-backup"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn a_write_never_re_blesses_tampering_done_since_opening() {
        let (dir, path, mut vault) = new_vault();
        vault.add("api/token", b"original", false).unwrap();
        let snapshot = dir.path().join("snap.db");
        fs::copy(&path, &snapshot).unwrap();
        vault.add("api/token", b"rotated", true).unwrap();
        // While this process has the vault open, someone without the keys
        // rolls the token back in the file.
        let conn = Connection::open(&path).unwrap();
        conn.execute(&format!("ATTACH '{}' AS old", snapshot.display()), [])
            .unwrap();
        conn.execute_batch(
            "UPDATE items SET blob = (SELECT blob FROM old.items o WHERE o.id = items.id)",
        )
        .unwrap();
        drop(conn);
        // The next write notices instead of signing over it.
        assert!(matches!(
            vault.add("note", b"x", false),
            Err(Error::Tampered)
        ));
        drop(vault);
        assert!(matches!(
            Vault::open(&path, b"correct horse"),
            Err(Error::Tampered)
        ));
    }

    #[test]
    fn a_whole_sensitive_item_outside_its_seal_is_refused() {
        let (_dir, path, mut vault) = new_vault();
        // Someone with the main key plants an unsplit "card" and re-MACs.
        let id = vault.item_id("cards/planted");
        let payload = encode_with(&STRUCTURED, "cards/planted", &visa()).unwrap();
        let blob = crypto::seal(&vault.keys.item, &vault.keys.item_aad(&id), &payload).unwrap();
        {
            let tx = vault.conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO items (id, blob) VALUES (?1, ?2)",
                params![id.as_slice(), blob],
            )
            .unwrap();
            bump_mac(&tx, &vault.keys).unwrap();
            tx.commit().unwrap();
        }
        drop(vault);
        let vault = Vault::open(&path, b"correct horse").unwrap();
        assert!(matches!(
            vault.item("cards/planted"),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn stronger_custom_kdf_settings_are_left_alone() {
        let target = KdfParams::default();
        let big_memory_one_pass = KdfParams {
            m_cost_kib: 1 << 20,
            t_cost: 1,
            p_cost: 4,
        };
        assert!(!weaker_than(big_memory_one_pass, target));
        assert!(weaker_than(
            KdfParams {
                m_cost_kib: 64 * 1024,
                t_cost: 3,
                p_cost: 1
            },
            target
        ));
    }

    #[test]
    fn a_redacted_copy_relabeled_to_another_kind_is_refused() {
        let (_dir, path, mut vault) = new_vault();
        let pair = crate::ssh::KeyPair::generate("me").unwrap();
        vault.put("ssh/id", &Item::ssh_key(&pair), false).unwrap();
        // Someone with the main key re-seals the redacted copy as a plain
        // "secret" and re-MACs, hoping an edit will save the private key
        // under the main key.
        let id = vault.item_id("ssh/id");
        let mut fake = vault.item("ssh/id").unwrap().redacted();
        fake.kind = Kind::Secret;
        let payload = encode_with(&REDACTED, "ssh/id", &fake).unwrap();
        let blob = crypto::seal(&vault.keys.item, &vault.keys.item_aad(&id), &payload).unwrap();
        {
            let tx = vault.conn.transaction().unwrap();
            tx.execute(
                "UPDATE items SET blob = ?2 WHERE id = ?1",
                params![id.as_slice(), blob],
            )
            .unwrap();
            bump_mac(&tx, &vault.keys).unwrap();
            tx.commit().unwrap();
        }
        drop(vault);
        let vault = Vault::open(&path, b"correct horse").unwrap();
        assert!(matches!(vault.item("ssh/id"), Err(Error::Corrupt(_))));
        assert!(matches!(
            vault.item_redacted("ssh/id"),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn only_one_process_upgrades_an_old_vault() {
        let dir = TempDir::new().unwrap();
        let (path, old_key) = legacy_vault(&dir, 2);
        // Process A opened the old vault before B upgraded it.
        let (mut a_conn, _) = connect_existing(&path).unwrap();
        let legacy = Keys::new(Zeroizing::new(*old_key), 2);
        let mut b = Vault::open(&path, b"correct horse").unwrap();
        b.add("added-by-b", b"keep me", false).unwrap();
        // A's upgrade sees it's done and backs off, instead of rewriting.
        assert!(
            upgrade(&mut a_conn, &path, &legacy, b"correct horse")
                .unwrap()
                .is_none()
        );
        drop(b);
        let after = Vault::open(&path, b"correct horse").unwrap();
        assert_eq!(value(&after, "added-by-b"), b"keep me");
    }

    #[test]
    fn a_rekey_that_cant_start_leaves_no_copy_behind() {
        let (_dir, path, mut vault) = new_vault();
        vault.add("api/token", b"t", false).unwrap();
        // Another process holds the write lock for longer than the timeout.
        let holder = Connection::open(&path).unwrap();
        holder.execute_batch("BEGIN IMMEDIATE").unwrap();
        vault
            .conn
            .busy_timeout(std::time::Duration::from_millis(50))
            .unwrap();
        assert!(vault.rekey(b"correct horse", None).is_err());
        holder.execute_batch("ROLLBACK").unwrap();
        let copies = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("backup"))
            .count();
        assert_eq!(copies, 0);
        // And the vault still works.
        vault.rekey(b"correct horse", None).unwrap();
        assert_eq!(value(&vault, "api/token"), b"t");
    }
}
