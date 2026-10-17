//! The audit log: one JSON line per AI-agent request, appended to
//! `audit.log` next to the vault (mode `0600`). It records who asked, for
//! what, which secret *names*, and what happened. It never records values.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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

pub fn path_for(vault: &Path) -> PathBuf {
    vault.with_file_name("audit.log")
}

pub fn record(log: &Path, event: &Event) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(log)
        .with_context(|| format!("could not open the audit log {}", log.display()))?;
    let mut line = serde_json::to_vec(event)?;
    line.push(b'\n');
    file.write_all(&line)?;
    Ok(())
}

/// The last `limit` events, oldest first. Unreadable lines are skipped.
pub fn recent(log: &Path, limit: usize) -> Result<Vec<Event>> {
    let file = match std::fs::File::open(log) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("could not read {}", log.display())),
    };
    let events: Vec<Event> = BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str(&line).ok())
        .collect();
    let skip = events.len().saturating_sub(limit);
    Ok(events.into_iter().skip(skip).collect())
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

    #[test]
    fn records_and_reads_back_recent_events() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("audit.log");
        for i in 0..5 {
            let event = Event {
                time: format_utc(i),
                client: "test".into(),
                tool: "list_secrets".into(),
                secrets: vec![],
                command: None,
                outcome: "approved".into(),
                exit_code: None,
                detail: None,
            };
            record(&log, &event).unwrap();
        }
        let last = recent(&log, 2).unwrap();
        assert_eq!(last.len(), 2);
        assert_eq!(last[1].time, format_utc(4));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(recent(&dir.path().join("missing"), 10).unwrap().is_empty());
    }
}
