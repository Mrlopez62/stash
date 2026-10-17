//! The on-disk vault: a SQLite file holding a password-wrapped vault key and
//! individually encrypted items.
//!
//! Layout (format version 2):
//!
//! - `meta` — KDF salt and parameters, plus the random vault key encrypted
//!   with the Argon2id key-encryption key (KEK). Changing the master password
//!   only re-wraps this one key.
//! - `items` — one row per item. The row id is `HMAC(index_key, name)`, so
//!   names are never stored in plaintext. The blob is the name and contents
//!   encrypted together with the vault key, with the row id as AAD so a blob
//!   can't be moved to another row.
//!
//! Item plaintext comes in two encodings:
//! - **secret** (v1 and v2): `u16 name length (LE) || name || raw value`.
//!   Any bytes work.
//! - **structured** (v2, logins and notes): `0xFFFF || u16 name length ||
//!   name || JSON item`. A real name length is at most 128, so the marker
//!   can't be mistaken for one.
//!
//! Version 2 only adds the structured encoding. Version 1 vaults open fine;
//! unlocking one with the master password upgrades its header to 2, so
//! older versions of stash refuse it instead of misreading new items.

use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use secrecy::SecretSlice;
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, SALT_LEN, SecretKey};
use crate::item::{FieldValue, Item, Kind};
use crate::reference::Reference;
use crate::{Error, Result, validate_name};

const FORMAT_VERSION: i64 = 2;
const OLDEST_SUPPORTED_VERSION: i64 = 1;
/// Marks the structured encoding (see the module docs).
const STRUCTURED: [u8; 2] = [0xFF, 0xFF];

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
}

const SCHEMA: &str = "
    CREATE TABLE meta  (key TEXT PRIMARY KEY, value ANY NOT NULL) STRICT;
    CREATE TABLE items (id BLOB PRIMARY KEY, blob BLOB NOT NULL) STRICT;
";

/// An unlocked vault. Keys are wiped from memory when this is dropped.
pub struct Vault {
    conn: Connection,
    vault_key: SecretKey,
    index_key: SecretKey,
    path: PathBuf,
    /// The header's format version. Structured items can only be written
    /// once it's current, so older versions of stash never see them.
    version: i64,
    /// A master-password unlock tried to upgrade the header but couldn't,
    /// because the file is read-only or in use.
    upgrade_blocked: bool,
}

impl Vault {
    /// Create a new, empty vault at `path`, protected by `password`.
    ///
    /// Fails with [`Error::VaultExists`] if a file is already there. On Unix the
    /// file is created with mode `0600` and missing parent directories `0700`.
    pub fn create(path: &Path, password: &[u8], params: KdfParams) -> Result<Self> {
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

        let result = Self::initialize(path, password, params);
        if result.is_err() {
            let _ = fs::remove_file(path);
        }
        result
    }

    fn initialize(path: &Path, password: &[u8], params: KdfParams) -> Result<Self> {
        let mut conn = connect(path)?;
        let salt: [u8; SALT_LEN] = crypto::random_bytes()?;
        let kek = crypto::derive_kek(password, &salt, params)?;
        let vault_key = crypto::random_key()?;
        let wrapped = crypto::seal(
            &kek,
            &header_aad(FORMAT_VERSION, params, &salt),
            vault_key.as_ref(),
        )?;

        let tx = conn.transaction()?;
        tx.execute_batch(SCHEMA)?;
        {
            let mut insert = tx.prepare("INSERT INTO meta (key, value) VALUES (?1, ?2)")?;
            insert.execute(params!["format_version", FORMAT_VERSION])?;
            insert.execute(params!["kdf_m_cost_kib", params.m_cost_kib])?;
            insert.execute(params!["kdf_t_cost", params.t_cost])?;
            insert.execute(params!["kdf_p_cost", params.p_cost])?;
            insert.execute(params!["kdf_salt", salt.as_slice()])?;
            insert.execute(params!["wrapped_key", wrapped])?;
            insert.execute(params!["key_check", key_check(&vault_key).as_slice()])?;
        }
        tx.commit()?;

        Ok(Self::from_parts(conn, vault_key, path, FORMAT_VERSION))
    }

    /// Open and unlock an existing vault with the master password.
    pub fn open(path: &Path, password: &[u8]) -> Result<Self> {
        let (mut conn, version) = connect_existing(path)?;
        let params = KdfParams {
            m_cost_kib: meta(&conn, "kdf_m_cost_kib")?,
            t_cost: meta(&conn, "kdf_t_cost")?,
            p_cost: meta(&conn, "kdf_p_cost")?,
        };
        let salt: Vec<u8> = meta(&conn, "kdf_salt")?;
        let wrapped: Vec<u8> = meta(&conn, "wrapped_key")?;

        let kek = crypto::derive_kek(password, &salt, params)?;
        let unwrapped = crypto::open(&kek, &header_aad(version, params, &salt), &wrapped)
            .map_err(|_| Error::WrongPassword)?;
        let mut vault_key = Zeroizing::new([0u8; crypto::KEY_LEN]);
        if unwrapped.len() != vault_key.len() {
            return Err(Error::Corrupt("vault key has the wrong length".into()));
        }
        vault_key.copy_from_slice(&unwrapped);

        // Header maintenance below tolerates a read-only or busy file: the
        // vault still opens, it just isn't upgraded this time. Any other
        // failure is a real error.

        // Vaults created before the key check existed get one on first unlock.
        let check = key_check(&vault_key);
        tolerate_unwritable(
            conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('key_check', ?1)",
                params![check.as_slice()],
            )
            .map_err(Error::from),
        )?;

        // Upgrade an older header: re-wrap the vault key bound to the current
        // version, so older versions of stash refuse the vault cleanly.
        let mut version = version;
        let mut upgrade_blocked = false;
        if version < FORMAT_VERSION {
            match tolerate_unwritable(upgrade_header(&mut conn, &kek, params, &salt, &vault_key))? {
                Some(()) => version = FORMAT_VERSION,
                None => upgrade_blocked = true,
            }
        }

        let mut vault = Self::from_parts(conn, vault_key, path, version);
        vault.upgrade_blocked = upgrade_blocked;
        Ok(vault)
    }

    /// Open an existing vault with its raw vault key, as handed back by
    /// Touch ID or the session agent. Fails with [`Error::WrongKey`] if the
    /// key doesn't belong to this vault.
    pub fn open_with_key(path: &Path, key: &[u8; crypto::KEY_LEN]) -> Result<Self> {
        let (conn, version) = connect_existing(path)?;
        let stored: Option<Vec<u8>> = conn
            .query_row("SELECT value FROM meta WHERE key = 'key_check'", [], |r| {
                r.get(0)
            })
            .optional()?;
        let vault_key = Zeroizing::new(*key);
        let expected = key_check(&vault_key);
        match stored {
            Some(stored) if crypto::ct_eq(&stored, &expected) => {
                Ok(Self::from_parts(conn, vault_key, path, version))
            }
            _ => Err(Error::WrongKey),
        }
    }

    fn from_parts(conn: Connection, vault_key: SecretKey, path: &Path, version: i64) -> Self {
        let index_key = Zeroizing::new(crypto::hmac(vault_key.as_ref(), b"stash/index-key/v1"));
        Self {
            conn,
            vault_key,
            index_key,
            path: path.to_owned(),
            version,
            upgrade_blocked: false,
        }
    }

    /// Whether the header is current, so logins and notes can be stored.
    /// A version 1 vault becomes current on its next master-password unlock.
    pub fn is_current(&self) -> bool {
        self.version >= FORMAT_VERSION
    }

    /// Why logins and notes can't be stored yet: the vault needs a
    /// master-password unlock, or that unlock couldn't write the upgrade.
    pub fn upgrade_error(&self) -> Error {
        if self.upgrade_blocked {
            Error::UpgradeBlocked
        } else {
            Error::NeedsUpgrade
        }
    }

    /// Whether an item with this name exists.
    pub fn contains(&self, name: &str) -> Result<bool> {
        validate_name(name)?;
        Ok(self.blob(&self.item_id(name))?.is_some())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The raw vault key, for handing to Touch ID enrollment or the session
    /// agent. Treat it like the master password.
    pub fn key(&self) -> &[u8; crypto::KEY_LEN] {
        &self.vault_key
    }

    /// Store a single-value secret. Fails with [`Error::AlreadyExists`]
    /// unless `overwrite` is set.
    pub fn add(&mut self, name: &str, value: &[u8], overwrite: bool) -> Result<()> {
        validate_name(name)?;
        let payload = encode_secret(name, value);
        self.write(name, &payload, overwrite)
    }

    /// Store an item. A plain secret (one value, no notes) uses the original
    /// encoding, so any version can read it; everything else uses the
    /// structured one, which needs a current header ([`Error::NeedsUpgrade`]
    /// otherwise). `updated` is set to now, and `created` too if it's 0.
    pub fn put(&mut self, name: &str, item: &Item, overwrite: bool) -> Result<()> {
        validate_name(name)?;
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
        let mut item = item.clone();
        item.updated = now;
        if item.created == 0 {
            item.created = now;
        }
        let payload = encode_structured(name, &item)?;
        self.write(name, &payload, overwrite)
    }

    fn write(&mut self, name: &str, payload: &[u8], overwrite: bool) -> Result<()> {
        let id = self.item_id(name);
        if !overwrite && self.blob(&id)?.is_some() {
            return Err(Error::AlreadyExists(name.to_owned()));
        }
        let blob = crypto::seal(&self.vault_key, &item_aad(&id), payload)?;
        self.conn.execute(
            "INSERT INTO items (id, blob) VALUES (?1, ?2)
             ON CONFLICT (id) DO UPDATE SET blob = excluded.blob",
            params![id.as_slice(), blob],
        )?;
        Ok(())
    }

    /// Read an item's main value: a secret's value, a login's password, a
    /// note's text.
    pub fn get(&self, name: &str) -> Result<SecretSlice<u8>> {
        match self
            .stored(name)?
            .ok_or_else(|| Error::NotFound(name.to_owned()))?
        {
            Stored::Secret(value) => Ok(SecretSlice::from(value.to_vec())),
            Stored::Structured(item) => item
                .primary()
                .map(|v| SecretSlice::from(v.as_bytes().to_vec()))
                .ok_or_else(|| Error::NoSuchField(name.to_owned(), "password".into())),
        }
    }

    /// Read a whole item. Single-value secrets come back as `Kind::Secret`
    /// items; binary ones fail with [`Error::NotText`] (use [`Vault::get`]).
    pub fn item(&self, name: &str) -> Result<Item> {
        match self
            .stored(name)?
            .ok_or_else(|| Error::NotFound(name.to_owned()))?
        {
            Stored::Secret(value) => {
                // Check before copying, so a failed conversion leaves no copy.
                let text =
                    std::str::from_utf8(&value).map_err(|_| Error::NotText(name.to_owned()))?;
                Ok(Item::secret(text))
            }
            Stored::Structured(item) => Ok(item),
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

    fn stored(&self, name: &str) -> Result<Option<Stored>> {
        validate_name(name)?;
        let id = self.item_id(name);
        let Some(blob) = self.blob(&id)? else {
            return Ok(None);
        };
        let payload = crypto::open(&self.vault_key, &item_aad(&id), &blob)?;
        let (stored_name, stored) = decode_item(&payload)?;
        if stored_name != name {
            return Err(Error::Corrupt(format!(
                "item `{name}` holds a different name"
            )));
        }
        Ok(Some(stored))
    }

    /// Delete a secret.
    pub fn remove(&mut self, name: &str) -> Result<()> {
        validate_name(name)?;
        let id = self.item_id(name);
        let deleted = self
            .conn
            .execute("DELETE FROM items WHERE id = ?1", params![id.as_slice()])?;
        if deleted == 0 {
            return Err(Error::NotFound(name.to_owned()));
        }
        Ok(())
    }

    /// All item names, sorted. Values are never returned, and item contents
    /// aren't even parsed.
    pub fn names(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT id, blob FROM items")?;
        let mut rows = stmt.query([])?;
        let mut names = Vec::new();
        while let Some(row) = rows.next()? {
            let id: Vec<u8> = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            let payload = crypto::open(&self.vault_key, &item_aad(&id), &blob)?;
            names.push(decode_name(&payload)?.to_owned());
        }
        names.sort();
        Ok(names)
    }

    /// One summary per item, sorted by name: kind, username, URL, whether it
    /// has 2FA. No secret values.
    pub fn summaries(&self) -> Result<Vec<Summary>> {
        let mut stmt = self.conn.prepare("SELECT id, blob FROM items")?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let id: Vec<u8> = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            let payload = crypto::open(&self.vault_key, &item_aad(&id), &blob)?;
            let (name, stored) = decode_item(&payload)?;
            out.push(match stored.structured() {
                None => Summary {
                    name,
                    kind: Kind::Secret,
                    username: None,
                    url: None,
                    has_otp: false,
                    updated: 0,
                },
                Some(item) => Summary {
                    name,
                    kind: item.kind,
                    username: item.username().map(str::to_owned),
                    url: item.url().map(str::to_owned),
                    has_otp: item.has_otp(),
                    updated: item.updated,
                },
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn item_id(&self, name: &str) -> [u8; 32] {
        crypto::hmac(self.index_key.as_ref(), name.as_bytes())
    }

    fn blob(&self, id: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row("SELECT blob FROM items WHERE id = ?1", params![id], |r| {
                r.get(0)
            })
            .optional()?)
    }
}

/// `Ok(None)` if the write failed only because the vault is read-only or
/// another process holds it; other errors pass through.
fn tolerate_unwritable<T>(result: Result<T>) -> Result<Option<T>> {
    use rusqlite::ErrorCode::{DatabaseBusy, DatabaseLocked, ReadOnly};
    match result {
        Ok(v) => Ok(Some(v)),
        Err(Error::Database(rusqlite::Error::SqliteFailure(e, _)))
            if matches!(e.code, ReadOnly | DatabaseBusy | DatabaseLocked) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn upgrade_header(
    conn: &mut Connection,
    kek: &SecretKey,
    params: KdfParams,
    salt: &[u8],
    vault_key: &SecretKey,
) -> Result<()> {
    let rewrapped = crypto::seal(
        kek,
        &header_aad(FORMAT_VERSION, params, salt),
        vault_key.as_ref(),
    )?;
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'wrapped_key'",
        params![rewrapped],
    )?;
    tx.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'format_version'",
        params![FORMAT_VERSION],
    )?;
    tx.commit()?;
    Ok(())
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

/// A value derived from the vault key that proves a key belongs to this
/// vault without revealing anything about it.
fn key_check(vault_key: &[u8; crypto::KEY_LEN]) -> [u8; 32] {
    crypto::hmac(vault_key, b"stash/key-check/v1")
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

/// AAD for the wrapped vault key: binds it to the format version, KDF
/// parameters, and salt so none of them can be swapped without detection.
fn header_aad(version: i64, params: KdfParams, salt: &[u8]) -> Vec<u8> {
    let mut aad = b"stash/vault-key/v1".to_vec();
    aad.extend_from_slice(&version.to_le_bytes());
    aad.extend_from_slice(&params.m_cost_kib.to_le_bytes());
    aad.extend_from_slice(&params.t_cost.to_le_bytes());
    aad.extend_from_slice(&params.p_cost.to_le_bytes());
    aad.extend_from_slice(salt);
    aad
}

fn item_aad(id: &[u8]) -> Vec<u8> {
    let mut aad = b"stash/item/v1".to_vec();
    aad.extend_from_slice(id);
    aad
}

/// A decrypted item, in whichever encoding it was stored.
enum Stored {
    Secret(Zeroizing<Vec<u8>>),
    Structured(Item),
}

impl Stored {
    fn structured(&self) -> Option<&Item> {
        match self {
            Stored::Structured(item) => Some(item),
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

/// `0xFFFF || u16 name length (LE) || name || JSON`.
fn encode_structured(name: &str, item: &Item) -> Result<Zeroizing<Vec<u8>>> {
    // Size the buffer up front so it never reallocates, which would leave
    // un-wiped copies of the JSON behind.
    let estimate = 256
        + item.notes.len() * 6
        + item
            .fields
            .iter()
            .map(|f| 64 + (f.label.len() + f.value.len()) * 6)
            .sum::<usize>();
    let mut json = Zeroizing::new(Vec::with_capacity(estimate));
    serde_json::to_writer(&mut *json, item)
        .map_err(|e| Error::Corrupt(format!("encoding item: {e}")))?;
    let mut out = Zeroizing::new(Vec::with_capacity(4 + name.len() + json.len()));
    out.extend_from_slice(&STRUCTURED);
    out.extend_from_slice(&name_header(name));
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/// Just the name, without parsing the contents.
fn decode_name(payload: &[u8]) -> Result<&str> {
    let corrupt = || Error::Corrupt("malformed item".into());
    let payload = payload.strip_prefix(&STRUCTURED).unwrap_or(payload);
    let (len, rest) = payload.split_first_chunk::<2>().ok_or_else(corrupt)?;
    let len = usize::from(u16::from_le_bytes(*len));
    let name = rest.get(..len).ok_or_else(corrupt)?;
    std::str::from_utf8(name).map_err(|_| corrupt())
}

fn decode_item(payload: &[u8]) -> Result<(String, Stored)> {
    let corrupt = || Error::Corrupt("malformed item".into());
    let (structured, payload) = match payload.strip_prefix(&STRUCTURED) {
        Some(rest) => (true, rest),
        None => (false, payload),
    };
    let (len, rest) = payload.split_first_chunk::<2>().ok_or_else(corrupt)?;
    let len = usize::from(u16::from_le_bytes(*len));
    if rest.len() < len {
        return Err(corrupt());
    }
    let (name, body) = rest.split_at(len);
    let name = std::str::from_utf8(name).map_err(|_| corrupt())?.to_owned();
    let stored = if structured {
        let item = serde_json::from_slice(body)
            .map_err(|e| Error::Corrupt(format!("item `{name}`: {e}")))?;
        Stored::Structured(item)
    } else {
        Stored::Secret(Zeroizing::new(body.to_vec()))
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

    #[test]
    fn older_vaults_get_a_key_check_on_password_unlock() {
        let (_dir, path, vault) = new_vault();
        let key = *vault.key();
        vault
            .conn
            .execute("DELETE FROM meta WHERE key = 'key_check'", [])
            .unwrap();
        drop(vault);

        assert!(matches!(
            Vault::open_with_key(&path, &key),
            Err(Error::WrongKey)
        ));
        drop(Vault::open(&path, b"correct horse").unwrap());
        assert!(Vault::open_with_key(&path, &key).is_ok());
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
    fn downgrade_to_v1(vault: &Vault) {
        let salt: Vec<u8> = meta(&vault.conn, "kdf_salt").unwrap();
        let kek = crypto::derive_kek(b"correct horse", &salt, FAST).unwrap();
        let wrapped = crypto::seal(&kek, &header_aad(1, FAST, &salt), vault.key()).unwrap();
        vault
            .conn
            .execute(
                "UPDATE meta SET value = ?1 WHERE key = 'wrapped_key'",
                params![wrapped],
            )
            .unwrap();
        vault
            .conn
            .execute("UPDATE meta SET value = 1 WHERE key = 'format_version'", [])
            .unwrap();
    }

    #[test]
    fn version_1_vaults_refuse_structured_items_until_upgraded() {
        // Regression: a v1 vault opened by key (Touch ID / session) used to
        // accept logins, which older versions of stash then misread.
        let (_dir, path, vault) = new_vault();
        let key = *vault.key();
        downgrade_to_v1(&vault);
        drop(vault);

        let mut by_key = Vault::open_with_key(&path, &key).unwrap();
        assert!(!by_key.is_current());
        assert!(matches!(
            by_key.put("github", &github_login(), false),
            Err(Error::NeedsUpgrade)
        ));
        // Plain secrets still work, in the encoding every version reads.
        by_key.add("tok", b"v", false).unwrap();
        drop(by_key);

        let mut by_password = Vault::open(&path, b"correct horse").unwrap();
        assert!(by_password.is_current());
        by_password.put("github", &github_login(), false).unwrap();
    }

    #[test]
    fn a_read_only_vault_still_opens_without_upgrading() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path, vault) = new_vault();
        downgrade_to_v1(&vault);
        drop(vault);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let opened = Vault::open(&path, b"correct horse");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut vault = opened.unwrap();
        assert!(!vault.is_current());
        // And says why, instead of asking for the unlock that just happened.
        assert!(matches!(
            vault.put("github", &github_login(), false),
            Err(Error::UpgradeBlocked)
        ));
    }

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
    fn version_1_vaults_open_and_upgrade_on_password_unlock() {
        let (_dir, path, mut vault) = new_vault();
        vault.add("old", b"value", false).unwrap();
        let key = *vault.key();
        downgrade_to_v1(&vault);
        drop(vault);

        // Touch ID / session keys still open it, without upgrading.
        drop(Vault::open_with_key(&path, &key).unwrap());
        let version = |p: &Path| -> i64 { meta(&connect(p).unwrap(), "format_version").unwrap() };
        assert_eq!(version(&path), 1);

        // The master password opens and upgrades it.
        let vault = Vault::open(&path, b"correct horse").unwrap();
        assert_eq!(value(&vault, "old"), b"value");
        drop(vault);
        assert_eq!(version(&path), 2);
        let vault = Vault::open(&path, b"correct horse").unwrap();
        assert_eq!(value(&vault, "old"), b"value");
    }

    #[test]
    fn rejects_vaults_from_the_future() {
        let (_dir, path, vault) = new_vault();
        vault
            .conn
            .execute("UPDATE meta SET value = 3 WHERE key = 'format_version'", [])
            .unwrap();
        drop(vault);
        assert!(matches!(
            Vault::open(&path, b"correct horse"),
            Err(Error::UnsupportedVersion(3))
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
}
