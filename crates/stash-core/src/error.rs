use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong master password (or the vault's header was modified)")]
    WrongPassword,
    #[error(
        "`{0}` is a card, bank account, or SSH key: reading its secret values takes Touch ID or the master password each time"
    )]
    SensitiveLocked(String),
    #[error(
        "the vault's keys were changed by another stash command (a new master password or `stash rekey`); unlock again"
    )]
    KeysChanged,
    #[error(
        "the vault's keys were replaced, but reopening it to double-check failed ({0}); the copy from before is at {1}"
    )]
    RekeyUnverified(String, PathBuf),
    #[error("this vault couldn't be upgraded: {0}")]
    UpgradeFailed(String),
    #[error(
        "the vault file was changed outside stash (items were added, removed, or rolled back), so stash won't trust it. Restore it from a backup you trust"
    )]
    Tampered,
    #[error(
        "this vault needs a one-time upgrade to the current format before it can be changed: run `stash upgrade` (it asks for your master password and keeps a backup)"
    )]
    NeedsUpgrade,
    #[error(
        "this vault couldn't be upgraded to store logins and notes because the file is read-only or in use by another stash process; fix its permissions or close the other process, then try again"
    )]
    UpgradeBlocked,
    #[error("`{0}` has no field `{1}`")]
    NoSuchField(String, String),
    #[error("`{0}` holds binary data, which only `stash get` can output")]
    NotText(String),
    #[error("{0}")]
    InvalidPayment(String),
    #[error("can't import this file: {0}")]
    Import(String),
    #[error("{0}")]
    InvalidSshKey(String),
    #[error("that SSH key file needs its passphrase (or the passphrase was wrong)")]
    SshPassphrase,
    #[error("invalid password rules: {0}")]
    InvalidRules(String),
    #[error("not a valid 2FA (TOTP) secret: {0}")]
    InvalidOtp(String),
    #[error("this key does not unlock the vault")]
    WrongKey,
    #[error("no secret named `{0}`")]
    NotFound(String),
    #[error("a secret named `{0}` already exists (use --force to overwrite)")]
    AlreadyExists(String),
    #[error("invalid secret name `{0}`: {1}")]
    InvalidName(String, &'static str),
    #[error("a vault already exists at {0}")]
    VaultExists(PathBuf),
    #[error("no vault at {0} (run `stash init` first)")]
    VaultMissing(PathBuf),
    #[error("vault format version {0} is not supported by this version of stash")]
    UnsupportedVersion(i64),
    #[error("vault is corrupt: {0}")]
    Corrupt(String),
    #[error("decryption failed (data was tampered with or the key is wrong)")]
    Decrypt,
    #[error("the system random number generator failed")]
    Rng,
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
