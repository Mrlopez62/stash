use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong master password")]
    WrongPassword,
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
