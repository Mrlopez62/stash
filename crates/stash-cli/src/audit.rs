//! The audit log: one line per request from an AI agent, the browser, or an
//! SSH client, appended to `audit.log` next to the vault (mode `0600`). It
//! records who asked, for what, which secret *names*, and what happened. It
//! never records values.
//!
//! Each line is sealed to the vault's audit public key (X25519, see
//! `Vault::audit_public_key`), so processes can add to the log while the
//! vault is locked, but reading it takes an unlocked vault: the names of
//! your secrets and the sites you fill aren't left in plain text.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use stash_core::{Vault, crypto};

use crate::filelock;

/// Binds sealed lines to this use.
const SEAL_LABEL: &[u8] = b"stash/v3/audit-line";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    /// UTC, RFC 3339.
    pub time: String,
    /// The MCP client, as it named itself (e.g. `claude-code`).
    pub client: String,
    pub tool: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// `approved`, `denied`, `blocked` (outside --allow), or `error`.
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// One line of the file.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Line {
    Sealed {
        sealed: String,
    },
    /// Written before v0.14, or while the vault had no audit key yet
    /// (names withheld then).
    Plain(Event),
}

/// Where a vault's log is, and which vault it's sealed for.
#[derive(Debug, Clone)]
pub struct Log {
    file: PathBuf,
    vault: PathBuf,
    /// The public key derived at this process's last unlock (see
    /// [`Log::pin`]).
    pinned: Option<[u8; 32]>,
}

impl Log {
    /// Seal from now on to the key this vault derives, rather than the one
    /// published in the vault file, which a program running as you could
    /// swap. Long-lived processes call this after each unlock.
    pub fn pin(&mut self, vault: &Vault) {
        if let Ok(secret) = vault.audit_secret() {
            self.pinned = Some(crypto::x25519_public(&secret));
        }
    }

    #[cfg(test)]
    pub fn file(&self) -> &Path {
        &self.file
    }
}

pub fn path_for(vault: &Path) -> Log {
    Log {
        file: vault.with_file_name("audit.log"),
        vault: vault.to_owned(),
        pinned: None,
    }
}

/// Add an event, sealed to the vault's audit key. If the vault doesn't
/// have one yet (it hasn't been unlocked since v0.14), the line keeps only
/// who asked, the tool, and the outcome: no names, commands, or sites.
pub fn record(log: &Log, event: &Event) -> Result<()> {
    let public = log
        .pinned
        .or_else(|| Vault::audit_public_key(&log.vault).ok().flatten());
    let line = match public {
        Some(public) => seal(&public, event)?,
        None => serde_json::to_vec(&Line::Plain(Event {
            secrets: Vec::new(),
            command: None,
            detail: Some("details withheld: unlock stash once to turn on the encrypted log".into()),
            ..event.clone()
        }))?,
    };
    let mut file = filelock::open_locked(&log.file)?;
    let mut line = line;
    line.push(b'\n');
    file.write_all(&line)?;
    Ok(())
}

fn seal(public: &[u8; 32], event: &Event) -> Result<Vec<u8>> {
    let plain = zeroize::Zeroizing::new(serde_json::to_vec(event)?);
    let sealed = crypto::seal_to(public, SEAL_LABEL, &plain)?;
    Ok(serde_json::to_vec(&Line::Sealed {
        sealed: BASE64.encode(sealed),
    })?)
}

/// What [`read`] found.
pub struct Contents {
    /// The last events asked for, oldest first.
    pub events: Vec<Event>,
    /// Sealed lines this vault's key can't open: written for older keys
    /// (before `stash rekey` couldn't reseal them) or not by stash.
    pub unreadable: usize,
    /// Lines still in plain text (from before the log was encrypted).
    pub plain: usize,
}

/// Read the log with an unlocked vault. Unparseable lines are skipped.
pub fn read(log: &Log, secret: &[u8; 32], limit: usize) -> Result<Contents> {
    let mut contents = Contents {
        events: Vec::new(),
        unreadable: 0,
        plain: 0,
    };
    for line in lines(&log.file)? {
        match line {
            Line::Plain(event) => {
                contents.plain += 1;
                contents.events.push(event);
            }
            Line::Sealed { sealed } => match open(secret, &sealed) {
                Some(event) => contents.events.push(event),
                None => contents.unreadable += 1,
            },
        }
    }
    let skip = contents.events.len().saturating_sub(limit);
    contents.events.drain(..skip);
    Ok(contents)
}

fn lines(path: &Path) -> Result<Vec<Line>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
    };
    Ok(BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str(&line).ok())
        .collect())
}

fn open(secret: &[u8; 32], sealed: &str) -> Option<Event> {
    let blob = BASE64.decode(sealed).ok()?;
    let plain = crypto::open_sealed(secret, SEAL_LABEL, &blob).ok()?;
    serde_json::from_slice(&plain).ok()
}

/// Seal every line to `public`: plain-text lines from before the log was
/// encrypted, and (with `old`) lines sealed to a vault's previous key, so
/// `stash passwd` and `stash rekey` don't lose the history. Lines that
/// can't be opened are kept as they are.
pub fn rewrite(log: &Log, old: Option<&[u8; 32]>, public: &[u8; 32]) -> Result<()> {
    let guard = filelock::open_locked(&log.file)?;
    let mut out = Vec::new();
    let mut changed = false;
    for line in lines(&log.file)? {
        let event = match &line {
            Line::Plain(event) => Some(event.clone()),
            Line::Sealed { sealed } => old.and_then(|old| open(old, sealed)),
        };
        let bytes = match event {
            Some(event) => {
                changed = true;
                seal(public, &event)?
            }
            None => serde_json::to_vec(&line)?,
        };
        out.extend(bytes);
        out.push(b'\n');
    }
    if !changed {
        return Ok(());
    }
    filelock::replace(&log.file, &out)?;
    drop(guard);
    Ok(())
}

pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format_utc(secs)
}

/// Seconds since the epoch → `YYYY-MM-DDTHH:MM:SSZ` (Howard Hinnant's
/// civil-from-days algorithm), to avoid a date-time dependency.
pub(crate) fn format_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

/// One line for `stash audit`.
pub fn describe(e: &Event) -> String {
    let mut line = format!(
        "{}  {:<12} {:<17} {:<8}",
        e.time.replace('T', " ").trim_end_matches('Z'),
        e.client,
        e.tool,
        e.outcome
    );
    if let Some(command) = &e.command {
        line.push_str(&format!(" `{command}`"));
    }
    if !e.secrets.is_empty() {
        line.push_str(&format!(" [{}]", e.secrets.join(", ")));
    }
    if let Some(code) = e.exit_code {
        line.push_str(&format!(" exit {code}"));
    }
    if let Some(detail) = &e.detail {
        line.push_str(&format!(" ({detail})"));
    }
    line
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn formats_utc_dates() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_utc(1_792_243_442), "2026-10-17T13:24:02Z");
    }

    fn event(i: u64, secret: &str) -> Event {
        Event {
            time: format_utc(i),
            client: "test".into(),
            tool: "get_secret".into(),
            secrets: vec![secret.into()],
            command: Some("deploy".into()),
            outcome: "approved".into(),
            exit_code: None,
            detail: Some("from example.com".into()),
        }
    }

    fn vault(dir: &TempDir) -> Vault {
        Vault::create(
            &dir.path().join("vault.db"),
            b"password",
            stash_core::KdfParams {
                m_cost_kib: 8,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap()
    }

    #[test]
    fn events_are_sealed_and_read_back_only_with_the_vault() {
        let dir = TempDir::new().unwrap();
        let vault = vault(&dir);
        let log = path_for(vault.path());
        for i in 0..5 {
            record(&log, &event(i, "github/token")).unwrap();
        }
        let raw = std::fs::read_to_string(log.file()).unwrap();
        assert_eq!(raw.lines().count(), 5);
        for hidden in ["github", "deploy", "example.com", "get_secret"] {
            assert!(!raw.contains(hidden), "{hidden} is in the log file");
        }

        let secret = vault.audit_secret().unwrap();
        let read = read(&log, &secret, 2).unwrap();
        assert_eq!(
            read.events,
            vec![event(3, "github/token"), event(4, "github/token")]
        );
        assert_eq!((read.unreadable, read.plain), (0, 0));
        let other = Vault::create(
            &dir.path().join("other.db"),
            b"password",
            stash_core::KdfParams {
                m_cost_kib: 8,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        let wrong = super::read(&log, &other.audit_secret().unwrap(), 10).unwrap();
        assert_eq!((wrong.events.len(), wrong.unreadable), (0, 5));

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(log.file()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn old_plain_lines_are_read_then_sealed_and_rekeys_keep_history() {
        let dir = TempDir::new().unwrap();
        let mut vault = vault(&dir);
        let log = path_for(vault.path());
        let mut legacy = serde_json::to_vec(&event(1, "aws/key")).unwrap();
        legacy.push(b'\n');
        std::fs::write(log.file(), legacy).unwrap();
        record(&log, &event(2, "github/token")).unwrap();

        let secret = vault.audit_secret().unwrap();
        let before = read(&log, &secret, 10).unwrap();
        assert_eq!((before.events.len(), before.plain), (2, 1));
        let public = crypto::x25519_public(&secret);
        rewrite(&log, None, &public).unwrap();
        assert!(!std::fs::read_to_string(log.file()).unwrap().contains("aws"));
        assert_eq!(read(&log, &secret, 10).unwrap().events, before.events);

        // New keys: the history is resealed to them.
        vault.rekey(b"password", None).unwrap();
        let new = vault.audit_secret().unwrap();
        assert_eq!(read(&log, &new, 10).unwrap().unreadable, 2);
        rewrite(&log, Some(&secret), &crypto::x25519_public(&new)).unwrap();
        assert_eq!(read(&log, &new, 10).unwrap().events, before.events);
    }

    #[test]
    fn a_pinned_key_ignores_a_swapped_public_key() {
        let dir = TempDir::new().unwrap();
        let vault = vault(&dir);
        let mut log = path_for(vault.path());
        log.pin(&vault);
        // Another program puts its own key in the vault file.
        let attacker = crypto::random_key().unwrap();
        rusqlite::Connection::open(vault.path())
            .unwrap()
            .execute(
                "UPDATE meta SET value = ?1 WHERE key = 'audit_public_key'",
                [crypto::x25519_public(&attacker).as_slice()],
            )
            .unwrap();
        record(&log, &event(1, "github/token")).unwrap();
        assert_eq!(
            read(&log, &vault.audit_secret().unwrap(), 10)
                .unwrap()
                .events
                .len(),
            1
        );
        assert!(read(&log, &attacker, 10).unwrap().events.is_empty());
    }

    #[test]
    fn without_an_audit_key_names_are_withheld() {
        let dir = TempDir::new().unwrap();
        let vault = vault(&dir);
        // A vault that hasn't been unlocked since the log was encrypted.
        rusqlite::Connection::open(vault.path())
            .unwrap()
            .execute("DELETE FROM meta WHERE key = 'audit_public_key'", [])
            .unwrap();
        let log = path_for(vault.path());
        record(&log, &event(1, "github/token")).unwrap();
        let raw = std::fs::read_to_string(log.file()).unwrap();
        assert!(raw.contains("approved") && !raw.contains("github") && !raw.contains("deploy"));
    }
}
