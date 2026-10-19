//! End-to-end tests for vault format 3: the separate sensitive key (cards,
//! bank accounts, SSH keys need a fresh Touch ID even during a session),
//! and replacing keys with `stash passwd` and `stash rekey`.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use tempfile::TempDir;

const PASSWORD: &str = "test-master-password";

/// The fake Touch ID helper used across the tests: logs prompts, declines
/// them while `deny` exists.
fn fake_touch_id(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("stash-touchid");
    std::fs::write(
        &path,
        r#"#!/bin/sh
d="$(dirname "$0")"
case "$1" in
  available) exit 0 ;;
  wrap) read k; echo "fake:$k" ;;
  unwrap) echo "unwrap: $2" >> "$d/prompts"; [ -e "$d/deny" ] && exit 2; read b; echo "${b#fake:}" ;;
  confirm) echo "confirm: $2" >> "$d/prompts"; [ -e "$d/deny" ] && exit 2; exit 0 ;;
  *) exit 1 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

struct Fixture {
    dir: TempDir,
    helper: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let helper = fake_touch_id(dir.path());
        let f = Self { dir, helper };
        f.with_password().arg("init").assert().success();
        f.with_password()
            .args(["touchid", "enable"])
            .assert()
            .success();
        f.with_password()
            .args([
                "add",
                "cards/visa",
                "--card",
                "--cardholder",
                "J Lopez",
                "--expiry",
                "08/27",
            ])
            .write_stdin("4242424242424242\n123\n")
            .assert()
            .success();
        f.with_password()
            .args(["add", "api/token"])
            .write_stdin("tok_123")
            .assert()
            .success();
        f
    }

    /// Like a user's shell: sessions and Touch ID, no password in the env.
    fn interactive(&self) -> Command {
        let mut cmd = Command::cargo_bin("stash").unwrap();
        cmd.env("STASH_VAULT", self.dir.path().join("vault.db"))
            .env("STASH_AGENT_SOCK", self.dir.path().join("agent.sock"))
            .env("STASH_TOUCHID_HELPER", &self.helper)
            .env_remove("STASH_PASSWORD")
            .env_remove("STASH_SESSION_TIMEOUT");
        cmd
    }

    fn with_password(&self) -> Command {
        let mut cmd = self.interactive();
        cmd.env("STASH_PASSWORD", PASSWORD)
            .env("STASH_SESSION_TIMEOUT", "0");
        cmd
    }

    fn prompts(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.path().join("prompts"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn stdout(&self, cmd: &mut Command) -> String {
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.interactive().arg("lock").output();
    }
}

#[test]
fn a_session_never_reads_a_card_without_a_fresh_touch_id() {
    let f = Fixture::new();
    // The first command unlocks with Touch ID and starts a session.
    f.stdout(f.interactive().arg("ls"));
    assert_eq!(f.prompts().len(), 1);
    // Ordinary secrets come from the session: no prompt.
    assert_eq!(
        f.stdout(f.interactive().args(["get", "api/token"])).trim(),
        "tok_123"
    );
    assert_eq!(f.prompts().len(), 1, "{:?}", f.prompts());
    // A card's values need a fresh fingerprint, every time.
    for _ in 0..2 {
        assert_eq!(
            f.stdout(f.interactive().args(["get", "cards/visa#cvv"]))
                .trim(),
            "123"
        );
    }
    let prompts = f.prompts();
    assert_eq!(prompts.len(), 3, "{prompts:?}");
    for p in &prompts[1..] {
        assert!(
            p.starts_with("unwrap: use a card, bank account, or SSH key for “get cards/visa#cvv”"),
            "{p}"
        );
    }
    // Showing a card without --reveal needs nothing.
    let shown = f.stdout(f.interactive().args(["show", "cards/visa"]));
    assert!(
        shown.contains("J Lopez") && !shown.contains("4242424242424242"),
        "{shown}"
    );
    assert_eq!(f.prompts().len(), 3);
    // Declining refuses.
    std::fs::write(f.dir.path().join("deny"), "").unwrap();
    f.interactive()
        .args(["get", "cards/visa"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("Touch ID was cancelled"));
}

#[test]
fn passwd_replaces_the_keys_and_keeps_touch_id_working() {
    let f = Fixture::new();
    let blob_before = std::fs::read_to_string(f.dir.path().join("vault.db.touchid")).unwrap();
    f.with_password()
        .arg("passwd")
        .env("STASH_NEW_PASSWORD", "a-brand-new-password")
        .assert()
        .success()
        .stderr(predicates::str::contains("replaced the vault's keys"));
    f.with_password().arg("ls").assert().failure();
    let mut new = f.with_password();
    new.env("STASH_PASSWORD", "a-brand-new-password");
    assert_eq!(f.stdout(new.args(["get", "cards/visa#cvv"])).trim(), "123");
    // Touch ID was re-enrolled with the new keys.
    let blob_after = std::fs::read_to_string(f.dir.path().join("vault.db.touchid")).unwrap();
    assert_ne!(blob_before, blob_after);
    assert_eq!(
        f.stdout(f.interactive().args(["get", "api/token"])).trim(),
        "tok_123"
    );
}

#[test]
fn rekey_keeps_the_password_but_not_the_keys() {
    let f = Fixture::new();
    let blob_before = std::fs::read_to_string(f.dir.path().join("vault.db.touchid")).unwrap();
    f.with_password().arg("rekey").assert().success();
    let blob_after = std::fs::read_to_string(f.dir.path().join("vault.db.touchid")).unwrap();
    assert_ne!(blob_before, blob_after);
    assert_eq!(
        f.stdout(f.with_password().args(["get", "cards/visa#number"]))
            .trim(),
        "4242424242424242"
    );
    f.with_password()
        .arg("upgrade")
        .assert()
        .success()
        .stderr(predicates::str::contains("already in the current format"));
}

#[test]
fn ai_agents_get_card_values_only_with_a_fresh_fingerprint() {
    let f = Fixture::new();
    let mut input = String::new();
    for line in [
        r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_secrets","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_with_secrets","arguments":{"command":["sh","-c","test \"$N\" = 4242424242424242"],"env":{"N":"stash://cards/visa"}}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_with_secrets","arguments":{"command":["sh","-c","test \"$N\" = 4242424242424242"],"env":{"N":"stash://cards/visa"}}}}"#,
    ] {
        input.push_str(line);
        input.push('\n');
    }
    let out = f
        .interactive()
        .args(["mcp", "--allow-payments"])
        .write_stdin(input)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines[2].contains("exit code 0"), "{}", lines[2]);
    assert!(lines[3].contains("exit code 0"), "{}", lines[3]);
    let prompts = f.prompts();
    // One unlock (listing), then each card use unwraps the key again; no
    // separate "confirm" is needed, the unwrap is the approval.
    assert_eq!(prompts.len(), 3, "{prompts:?}");
    assert!(
        prompts
            .iter()
            .skip(1)
            .all(|p| p.starts_with("unwrap: let test run")),
        "{prompts:?}"
    );
}
