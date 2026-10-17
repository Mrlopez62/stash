use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const PASSWORD: &str = "test-master-password";

fn stash(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("stash").unwrap();
    cmd.env("STASH_VAULT", dir.path().join("vault.db"))
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
