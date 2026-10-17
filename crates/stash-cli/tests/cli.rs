use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const PASSWORD: &str = "test-master-password";

fn stash(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("stash").unwrap();
    cmd.env("STASH_VAULT", dir.path().join("vault.db"))
        .env("STASH_AGENT_SOCK", dir.path().join("agent.sock"))
        .env("STASH_PASSWORD", PASSWORD);
    cmd
}

fn init() -> TempDir {
    let dir = TempDir::new().unwrap();
    stash(&dir).arg("init").assert().success();
    dir
}

#[test]
fn full_round_trip() {
    let dir = init();

    stash(&dir)
        .args(["add", "github/token"])
        .write_stdin("ghp_abc123\n")
        .assert()
        .success();
    stash(&dir)
        .args(["add", "aws/key"])
        .write_stdin("AKIA")
        .assert()
        .success();

    // Trailing newline from stdin is dropped; no newline added when piped.
    stash(&dir)
        .args(["get", "github/token"])
        .assert()
        .success()
        .stdout("ghp_abc123");
    stash(&dir)
        .arg("ls")
        .assert()
        .success()
        .stdout("aws/key\ngithub/token\n");

    stash(&dir).args(["rm", "aws/key"]).assert().success();
    stash(&dir)
        .arg("ls")
        .assert()
        .success()
        .stdout("github/token\n");
}

#[test]
fn wrong_password_fails() {
    let dir = init();
    stash(&dir)
        .env("STASH_PASSWORD", "not-the-password")
        .arg("ls")
        .assert()
        .failure()
        .stderr(predicate::str::contains("wrong master password"));
}

#[test]
fn duplicate_add_needs_force() {
    let dir = init();
    stash(&dir)
        .args(["add", "k"])
        .write_stdin("one")
        .assert()
        .success();
    stash(&dir)
        .args(["add", "k"])
        .write_stdin("two")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
    stash(&dir)
        .args(["add", "k", "--force"])
        .write_stdin("two")
        .assert()
        .success();
    stash(&dir).args(["get", "k"]).assert().stdout("two");
}

#[test]
fn missing_vault_and_missing_secret_are_clear_errors() {
    let dir = TempDir::new().unwrap();
    stash(&dir)
        .arg("ls")
        .assert()
        .failure()
        .stderr(predicate::str::contains("stash init"));

    let dir = init();
    stash(&dir)
        .args(["get", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no secret named `nope`"));
}

#[test]
fn init_refuses_short_password_and_existing_vault() {
    let dir = TempDir::new().unwrap();
    stash(&dir)
        .env("STASH_PASSWORD", "short")
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("at least 8"));

    let dir = init();
    stash(&dir)
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

/// A stand-in for the Swift helper that "wraps" by prefixing, so the full
/// Touch ID and session flow can be tested on any OS without a fingerprint.
/// Each unwrap (i.e. each Touch ID prompt) appends a line to `unwraps`.
fn fake_touch_id(dir: &TempDir) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.path().join("stash-touchid");
    std::fs::write(
        &path,
        r#"#!/bin/sh
case "$1" in
  available) exit 0 ;;
  wrap) read k; echo "fake:$k" ;;
  unwrap) echo x >> "$(dirname "$0")/unwraps"; read b; echo "${b#fake:}" ;;
  *) exit 1 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn prompts(dir: &TempDir) -> usize {
    std::fs::read_to_string(dir.path().join("unwraps"))
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

/// Like `stash()`, but with no password in the environment, so unlocking has
/// to go through a session or Touch ID.
fn stash_interactive(dir: &TempDir, helper: &std::path::Path) -> Command {
    let mut cmd = stash(dir);
    cmd.env_remove("STASH_PASSWORD")
        .env("STASH_TOUCHID_HELPER", helper);
    cmd
}

fn init_with_touch_id() -> (TempDir, std::path::PathBuf) {
    let dir = init();
    let helper = fake_touch_id(&dir);
    stash(&dir)
        .env("STASH_TOUCHID_HELPER", &helper)
        .args(["touchid", "enable"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Touch ID unlock is on"));
    stash(&dir)
        .args(["add", "k"])
        .write_stdin("v")
        .assert()
        .success();
    (dir, helper)
}

#[test]
fn touch_id_unlocks_without_the_password() {
    let (dir, helper) = init_with_touch_id();
    stash_interactive(&dir, &helper)
        .env("STASH_SESSION_TIMEOUT", "0")
        .args(["get", "k"])
        .assert()
        .success()
        .stdout("v");
    assert_eq!(prompts(&dir), 1);

    // Sessions off: every command asks again.
    stash_interactive(&dir, &helper)
        .env("STASH_SESSION_TIMEOUT", "0")
        .arg("ls")
        .assert()
        .success();
    assert_eq!(prompts(&dir), 2);
}

#[test]
fn session_reuses_one_unlock_until_locked() {
    let (dir, helper) = init_with_touch_id();
    let run = |args: &[&str]| {
        stash_interactive(&dir, &helper)
            .env("STASH_SESSION_TIMEOUT", "30")
            .args(args)
            .assert()
            .success();
    };

    run(&["get", "k"]);
    run(&["ls"]);
    run(&["get", "k"]);
    assert_eq!(
        prompts(&dir),
        1,
        "one Touch ID prompt for the whole session"
    );

    run(&["lock"]);
    run(&["ls"]);
    assert_eq!(prompts(&dir), 2, "locking ends the session");

    run(&["lock"]); // stop the agent
}

#[test]
fn touch_id_status_and_disable() {
    let (dir, helper) = init_with_touch_id();
    stash_interactive(&dir, &helper)
        .args(["touchid", "status"])
        .assert()
        .success()
        .stdout("Touch ID available: yes\nTouch ID unlock on: yes\n");
    stash_interactive(&dir, &helper)
        .args(["touchid", "disable"])
        .assert()
        .success();
    stash_interactive(&dir, &helper)
        .args(["touchid", "status"])
        .assert()
        .stdout(predicate::str::contains("Touch ID unlock on: no"));
}

#[test]
fn touch_id_enable_requires_the_helper() {
    let dir = init();
    stash(&dir)
        .env("STASH_TOUCHID_HELPER", dir.path().join("missing"))
        .args(["touchid", "enable"])
        .assert()
        .failure();
}

// ---- stash run / stash inject ----

fn init_with_secrets() -> TempDir {
    let dir = init();
    for (name, value) in [
        ("github/token", "ghp_abc123"),
        ("db/url", "postgres://u:p@h/db"),
    ] {
        stash(&dir)
            .args(["add", name])
            .write_stdin(value)
            .assert()
            .success();
    }
    dir
}

#[test]
fn run_injects_references_from_env_files_and_masks_output() {
    let dir = init_with_secrets();
    let env = dir.path().join(".env");
    std::fs::write(&env, "TOKEN=stash://github/token\nPLAIN=hello\n").unwrap();

    stash(&dir)
        .args(["run", "--env-file"])
        .arg(&env)
        .args([
            "--",
            "sh",
            "-c",
            r#"echo "$PLAIN $TOKEN"; echo "err $TOKEN" >&2"#,
        ])
        .assert()
        .success()
        .stdout("hello <concealed by stash>\n")
        .stderr("err <concealed by stash>\n");
}

#[test]
fn run_without_masking_passes_values_through() {
    let dir = init_with_secrets();
    stash(&dir)
        .env("TOKEN", "stash://github/token")
        .args([
            "run",
            "--no-masking",
            "--",
            "sh",
            "-c",
            r#"printf %s "$TOKEN""#,
        ])
        .assert()
        .success()
        .stdout("ghp_abc123");
}

#[test]
fn run_resolves_references_in_the_inherited_environment() {
    let dir = init_with_secrets();
    // The child proves it got the real value without printing it.
    stash(&dir)
        .env("DATABASE_URL", "stash://db/url")
        .args([
            "run",
            "--",
            "sh",
            "-c",
            r#"test "$DATABASE_URL" = "postgres://u:p@h/db""#,
        ])
        .assert()
        .success();
}

#[test]
fn run_passes_through_exit_codes_and_never_leaks_the_master_password() {
    let dir = init_with_secrets();
    stash(&dir)
        .args(["run", "--", "sh", "-c", "exit 7"])
        .assert()
        .code(7);
    stash(&dir)
        .args([
            "run",
            "--",
            "sh",
            "-c",
            r#"printf %s "${STASH_PASSWORD-unset}""#,
        ])
        .assert()
        .success()
        .stdout("unset");
}

#[test]
fn run_needs_no_unlock_without_references() {
    let dir = init_with_secrets();
    // A wrong password would fail any unlock; with no references none happens.
    stash(&dir)
        .env("STASH_PASSWORD", "wrong-password")
        .args(["run", "--", "true"])
        .assert()
        .success();
}

#[test]
fn run_reports_missing_secrets_and_commands() {
    let dir = init_with_secrets();
    stash(&dir)
        .env("TOKEN", "stash://nope")
        .args(["run", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("resolving TOKEN"))
        .stderr(predicate::str::contains("no secret named `nope`"));
    stash(&dir)
        .args(["run", "--", "definitely-not-a-command-xyz"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "command not found: definitely-not-a-command-xyz",
        ));
}

#[test]
fn get_accepts_a_reference() {
    let dir = init_with_secrets();
    stash(&dir)
        .args(["get", "stash://github/token"])
        .assert()
        .success()
        .stdout("ghp_abc123");
}

#[test]
fn inject_fills_templates_into_a_private_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = init_with_secrets();
    let tpl = dir.path().join("config.tpl.yml");
    let out = dir.path().join("config.yml");
    std::fs::write(
        &tpl,
        "db: {{ stash://db/url }}\ntoken: {{stash://github/token}}\nkeep: {{ other }}\n",
    )
    .unwrap();

    stash(&dir)
        .args(["inject", "-i"])
        .arg(&tpl)
        .arg("-o")
        .arg(&out)
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        "db: postgres://u:p@h/db\ntoken: ghp_abc123\nkeep: {{ other }}\n"
    );
    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    // Refuses to overwrite without --force.
    stash(&dir)
        .args(["inject", "-i"])
        .arg(&tpl)
        .arg("-o")
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn inject_writes_nothing_when_a_reference_is_missing() {
    let dir = init_with_secrets();
    let out = dir.path().join("out.txt");
    stash(&dir)
        .args(["inject", "-o"])
        .arg(&out)
        .write_stdin("ok: {{ stash://db/url }}\nbad: {{ stash://missing }}\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("no secret named `missing`"));
    assert!(!out.exists());

    stash(&dir)
        .arg("inject")
        .write_stdin("x={{ stash://github/token }}")
        .assert()
        .success()
        .stdout("x=ghp_abc123");
}
