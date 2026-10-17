//! Touch ID unlock through the `stash-touchid` Swift helper.
//!
//! On `stash touchid enable`, the helper encrypts the vault key to a Secure
//! Enclave key that only works after a Touch ID match. The result is an
//! opaque blob saved next to the vault as `<vault>.touchid`. Unlocking hands
//! the blob back to the helper, which prompts for a fingerprint and returns
//! the vault key. Keys always travel over pipes, never in arguments.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use stash_core::crypto::{self, SecretKey};
use zeroize::Zeroizing;

const HELPER_NAME: &str = "stash-touchid";

pub fn blob_path(vault: &Path) -> PathBuf {
    let mut path = vault.as_os_str().to_owned();
    path.push(".touchid");
    PathBuf::from(path)
}

/// Find the helper: `$STASH_TOUCHID_HELPER`, then next to this binary, then `$PATH`.
pub fn helper() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("STASH_TOUCHID_HELPER") {
        return Some(PathBuf::from(path));
    }
    let beside_exe = std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.join(HELPER_NAME)));
    let on_path = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(HELPER_NAME));
    beside_exe.into_iter().chain(on_path).find(|p| p.is_file())
}

pub enum UnlockError {
    /// The user dismissed the Touch ID prompt.
    Cancelled,
    /// Touch ID can't be used right now (no sensor, lid closed, lockout,
    /// fingerprints changed). Falling back to the password is expected.
    Unavailable(String),
    Failed(String),
}

struct Output {
    code: Option<i32>,
    stdout: Zeroizing<String>,
    stderr: String,
}

fn run(helper: &Path, args: &[&str], stdin: &str) -> Result<Output> {
    let mut child = Command::new(helper)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("could not run {}", helper.display()))?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(stdin.as_bytes())?;
    let out = child.wait_with_output()?;
    Ok(Output {
        code: out.status.code(),
        stdout: Zeroizing::new(String::from_utf8_lossy(&out.stdout).trim().to_owned()),
        stderr: String::from_utf8_lossy(&out.stderr)
            .trim()
            .trim_start_matches("stash-touchid: ")
            .to_owned(),
    })
}

/// Whether Touch ID is usable right now, or why not.
pub fn availability(helper: &Path) -> Result<(), String> {
    match run(helper, &["available"], "") {
        Ok(out) if out.code == Some(0) => Ok(()),
        Ok(out) => Err(out.stderr),
        Err(e) => Err(format!("{e:#}")),
    }
}

/// Protect `key` with Touch ID and save the blob next to the vault.
pub fn enroll(helper: &Path, vault: &Path, key: &[u8; 32]) -> Result<()> {
    if let Err(why) = availability(helper) {
        bail!("{why}");
    }
    let hex = crypto::to_hex(key);
    let out = run(helper, &["wrap"], &hex)?;
    if out.code != Some(0) || out.stdout.is_empty() {
        bail!("Touch ID enrollment failed: {}", out.stderr);
    }
    let path = blob_path(vault);
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut file = opts
        .open(&path)
        .with_context(|| format!("could not write {}", path.display()))?;
    writeln!(file, "{}", out.stdout.as_str())?;
    Ok(())
}

pub fn is_enrolled(vault: &Path) -> bool {
    blob_path(vault).is_file()
}

pub fn disable(vault: &Path) -> Result<bool> {
    match fs::remove_file(blob_path(vault)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Prompt for a fingerprint and recover the vault key.
/// `reason` finishes the system dialog's sentence "stash-touchid is trying to …".
pub fn unlock(helper: &Path, vault: &Path, reason: &str) -> Result<SecretKey, UnlockError> {
    let blob = fs::read_to_string(blob_path(vault))
        .map_err(|e| UnlockError::Failed(format!("could not read Touch ID data: {e}")))?;
    let out = run(helper, &["unwrap", reason], &blob)
        .map_err(|e| UnlockError::Unavailable(format!("{e:#}")))?;
    match out.code {
        Some(0) => crypto::key_from_hex(&out.stdout)
            .ok_or_else(|| UnlockError::Failed("helper returned a malformed key".into())),
        Some(2) => Err(UnlockError::Cancelled),
        Some(3) => Err(UnlockError::Unavailable(out.stderr)),
        _ => Err(UnlockError::Failed(out.stderr)),
    }
}

/// Ask for a fingerprint to approve an action, without unwrapping anything.
/// `reason` finishes the sentence "stash-touchid is trying to …".
pub fn confirm(helper: &Path, reason: &str) -> Result<(), UnlockError> {
    let out = run(helper, &["confirm", reason], "")
        .map_err(|e| UnlockError::Unavailable(format!("{e:#}")))?;
    match out.code {
        Some(0) => Ok(()),
        Some(2) => Err(UnlockError::Cancelled),
        Some(3) => Err(UnlockError::Unavailable(out.stderr)),
        _ => Err(UnlockError::Failed(out.stderr)),
    }
}
