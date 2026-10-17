//! The on-disk vault: a SQLite file holding a password-wrapped vault key and
//! individually encrypted items.
//!
//! Layout (format version 1):
//!
//! - `meta` — KDF salt and parameters, plus the random vault key encrypted
//!   with the Argon2id key-encryption key (KEK). Changing the master password
//!   only re-wraps this one key.
//! - `items` — one row per secret. The row id is `HMAC(index_key, name)`, so
//!   names are never stored in plaintext. The blob is the name and value
//!   encrypted together with the vault key, with the row id as AAD so a blob
//!   can't be moved to another row.

use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use secrecy::SecretSlice;
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, SALT_LEN, SecretKey};
use crate::{Error, Result, validate_name};

const FORMAT_VERSION: i64 = 1;

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
        let wrapped = crypto::seal(&kek, &header_aad(params, &salt), vault_key.as_ref())?;

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
        }
        tx.commit()?;

        Ok(Self::from_parts(conn, vault_key, path))
    }

    /// Open and unlock an existing vault.
    pub fn open(path: &Path, password: &[u8]) -> Result<Self> {
        if !path.exists() {
            return Err(Error::VaultMissing(path.to_owned()));
        }
        let conn = connect(path)?;

        let version: i64 = meta(&conn, "format_version")?;
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let params = KdfParams {
            m_cost_kib: meta(&conn, "kdf_m_cost_kib")?,
            t_cost: meta(&conn, "kdf_t_cost")?,
            p_cost: meta(&conn, "kdf_p_cost")?,
        };
        let salt: Vec<u8> = meta(&conn, "kdf_salt")?;
        let wrapped: Vec<u8> = meta(&conn, "wrapped_key")?;

        let kek = crypto::derive_kek(password, &salt, params)?;
        let unwrapped = crypto::open(&kek, &header_aad(params, &salt), &wrapped)
            .map_err(|_| Error::WrongPassword)?;
        let mut vault_key = Zeroizing::new([0u8; crypto::KEY_LEN]);
        if unwrapped.len() != vault_key.len() {
            return Err(Error::Corrupt("vault key has the wrong length".into()));
        }
        vault_key.copy_from_slice(&unwrapped);

        Ok(Self::from_parts(conn, vault_key, path))
    }

    fn from_parts(conn: Connection, vault_key: SecretKey, path: &Path) -> Self {
        let index_key = Zeroizing::new(crypto::hmac(vault_key.as_ref(), b"stash/index-key/v1"));
        Self {
            conn,
            vault_key,
            index_key,
            path: path.to_owned(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Store a secret. Fails with [`Error::AlreadyExists`] unless `overwrite` is set.
    pub fn add(&mut self, name: &str, value: &[u8], overwrite: bool) -> Result<()> {
        validate_name(name)?;
        let id = self.item_id(name);
        if !overwrite && self.blob(&id)?.is_some() {
            return Err(Error::AlreadyExists(name.to_owned()));
        }
        let payload = encode_item(name, value);
        let blob = crypto::seal(&self.vault_key, &item_aad(&id), &payload)?;
        self.conn.execute(
            "INSERT INTO items (id, blob) VALUES (?1, ?2)
             ON CONFLICT (id) DO UPDATE SET blob = excluded.blob",
            params![id.as_slice(), blob],
        )?;
        Ok(())
    }

    /// Read a secret's value.
    pub fn get(&self, name: &str) -> Result<SecretSlice<u8>> {
        validate_name(name)?;
        let id = self.item_id(name);
        let blob = self
            .blob(&id)?
            .ok_or_else(|| Error::NotFound(name.to_owned()))?;
        let payload = crypto::open(&self.vault_key, &item_aad(&id), &blob)?;
        let (stored_name, value) = decode_item(&payload)?;
        if stored_name != name {
            return Err(Error::Corrupt(format!(
                "item `{name}` holds a different name"
            )));
        }
        Ok(SecretSlice::from(value.to_vec()))
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

    /// All secret names, sorted. Values are never returned.
    pub fn names(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT id, blob FROM items")?;
        let mut rows = stmt.query([])?;
        let mut names = Vec::new();
        while let Some(row) = rows.next()? {
            let id: Vec<u8> = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            let payload = crypto::open(&self.vault_key, &item_aad(&id), &blob)?;
            let (name, _) = decode_item(&payload)?;
            names.push(name.to_owned());
        }
        names.sort();
        Ok(names)
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

fn connect(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // Overwrite deleted rows with zeros instead of leaving them in free pages.
    conn.execute_batch("PRAGMA secure_delete = ON;")?;
    Ok(conn)
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
fn header_aad(params: KdfParams, salt: &[u8]) -> Vec<u8> {
    let mut aad = b"stash/vault-key/v1".to_vec();
    aad.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
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

/// Item plaintext: `u16 name length (LE) || name || value`.
fn encode_item(name: &str, value: &[u8]) -> Zeroizing<Vec<u8>> {
    let len = u16::try_from(name.len()).expect("names are validated to be short");
    let mut out = Zeroizing::new(Vec::with_capacity(2 + name.len() + value.len()));
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(value);
    out
}

fn decode_item(payload: &[u8]) -> Result<(&str, &[u8])> {
    let corrupt = || Error::Corrupt("malformed item".into());
    let (len, rest) = payload.split_first_chunk::<2>().ok_or_else(corrupt)?;
    let len = usize::from(u16::from_le_bytes(*len));
    if rest.len() < len {
        return Err(corrupt());
    }
    let (name, value) = rest.split_at(len);
    Ok((std::str::from_utf8(name).map_err(|_| corrupt())?, value))
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
}
