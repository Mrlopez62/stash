//! Small files that several stash processes append to or rewrite (the audit
//! log, the list of approved files): an exclusive lock for each change, and
//! rewrites that replace the file whole.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use anyhow::{Context, Result};

/// `path`, created `0600` if missing, opened for appending and locked
/// against other stash processes until the file is dropped. If a
/// [`replace`] swapped the file while we waited, lock the new one instead.
pub fn open_locked(path: &Path) -> Result<File> {
    loop {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("could not open {}", path.display()))?;
        // SAFETY: a valid descriptor; the lock is released when it's closed.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("could not lock {}", path.display()));
        }
        let current = std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()));
        let opened = file.metadata()?;
        if current == Some((opened.dev(), opened.ino())) {
            return Ok(file);
        }
    }
}

/// Replace `path` with `contents` (mode `0600`) in one step. Call while
/// holding [`open_locked`] on it.
pub fn replace(path: &Path, contents: &[u8]) -> Result<()> {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(".tmp");
    let tmp = path.with_file_name(name);
    let _ = std::fs::remove_file(&tmp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("could not write {}", tmp.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
