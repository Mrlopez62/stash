//! Copy to the system clipboard, and clear it again after a while.
//!
//! Clearing is done by a small detached `stash clipboard-clear` process. It
//! gets only a SHA-256 hash of what was copied, never the value, and clears
//! the clipboard only if it still holds that exact value, so it never wipes
//! something you copied since.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Seconds before a copied secret is cleared. `0` keeps it.
const TIMEOUT_ENV: &str = "STASH_CLIPBOARD_TIMEOUT";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// A program that takes `copy` (stdin → clipboard) or `paste` (clipboard →
/// stdout), used instead of the system tools. For tests.
const HELPER_ENV: &str = "STASH_CLIPBOARD_HELPER";

pub fn timeout() -> Result<Option<Duration>> {
    match std::env::var(TIMEOUT_ENV) {
        Err(_) => Ok(Some(DEFAULT_TIMEOUT)),
        Ok(v) => {
            let secs: u64 = v
                .trim()
                .parse()
                .with_context(|| format!("{TIMEOUT_ENV} must be a number of seconds"))?;
            Ok((secs > 0).then(|| Duration::from_secs(secs)))
        }
    }
}

enum Op {
    Copy,
    Paste,
}

fn command(op: Op) -> Result<Command> {
    if let Some(helper) = std::env::var_os(HELPER_ENV) {
        let mut cmd = Command::new(helper);
        cmd.arg(match op {
            Op::Copy => "copy",
            Op::Paste => "paste",
        });
        return Ok(cmd);
    }
    if cfg!(target_os = "macos") {
        return Ok(Command::new(match op {
            Op::Copy => "pbcopy",
            Op::Paste => "pbpaste",
        }));
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        let mut cmd = Command::new(match op {
            Op::Copy => "wl-copy",
            Op::Paste => "wl-paste",
        });
        if matches!(op, Op::Paste) {
            cmd.arg("--no-newline");
        }
        return Ok(cmd);
    }
    let mut cmd = Command::new("xclip");
    cmd.args(["-selection", "clipboard"]);
    if matches!(op, Op::Paste) {
        cmd.arg("-o");
    }
    Ok(cmd)
}

/// Put `value` on the clipboard. The value goes through a pipe, never argv.
pub fn copy(value: &[u8]) -> Result<()> {
    let mut child = command(Op::Copy)?
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("could not reach the clipboard (pbcopy, wl-copy, or xclip)")?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(value)?;
    if !child.wait()?.success() {
        bail!("copying to the clipboard failed");
    }
    Ok(())
}

fn paste() -> Result<Zeroizing<Vec<u8>>> {
    let mut child = command(Op::Paste)?
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut out = Zeroizing::new(Vec::new());
    child
        .stdout
        .take()
        .expect("stdout is piped")
        .read_to_end(&mut out)?;
    child.wait()?;
    Ok(out)
}

fn digest(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Start a detached process that clears the clipboard after `after`, if it
/// still holds `value`.
pub fn clear_later(value: &[u8], after: Duration) -> Result<()> {
    let mut child = Command::new(std::env::current_exe()?)
        .args(["clipboard-clear", "--after", &after.as_secs().to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Survives the terminal closing and Ctrl-C.
        .process_group(0)
        .spawn()
        .context("could not schedule clearing the clipboard")?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(digest(value).as_bytes())?;
    Ok(())
}

/// The body of `stash clipboard-clear`: read the expected hash from stdin,
/// wait, then clear if unchanged.
pub fn clear_if_unchanged(after: Duration) -> Result<()> {
    let mut expected = String::new();
    std::io::stdin().read_to_string(&mut expected)?;
    std::thread::sleep(after);
    if digest(&paste()?) == expected.trim() {
        copy(b"")?;
    }
    Ok(())
}
