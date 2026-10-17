//! End-to-end tests for logins, notes, editing, showing, and generating.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const PASSWORD: &str = "test-master-password";
const OTP_SECRET: &str = "JBSWY3DPEHPK3PXP";

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

fn out(dir: &TempDir, args: &[&str]) -> String {
    let o = stash(dir)
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(o).unwrap()
}

fn github(dir: &TempDir) {
    stash(dir)
        .args(["add", "github", "--login", "--username", "octocat"])
        .args(["--url", "https://github.com"])
        .write_stdin("hunter2!\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("Saved login github"));
}

#[test]
fn logins_have_fields_you_can_reference() {
    let dir = init();
    github(&dir);
    assert_eq!(out(&dir, &["get", "github"]), "hunter2!");
    assert_eq!(out(&dir, &["get", "github#username"]), "octocat");
    assert_eq!(
        out(&dir, &["get", "stash://github#website"]),
        "https://github.com"
    );
    stash(&dir)
        .args(["get", "github#nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("`github` has no field `nope`"));

    // References work in run and inject, with output masking as usual.
    let env = dir.path().join(".env");
    std::fs::write(&env, "U=stash://github#username\nP=stash://github\n").unwrap();
    stash(&dir)
        .args(["run", "--env-file"])
        .arg(&env)
        .args(["--", "sh", "-c", r#"echo "$U:$P""#])
        .assert()
        .success()
        .stdout("<concealed by stash>:<concealed by stash>\n");
    stash(&dir)
        .arg("inject")
        .write_stdin("user={{ stash://github#username }}")
        .assert()
        .stdout("user=octocat");
}

#[test]
fn generated_passwords_are_never_printed_by_add() {
    let dir = init();
    stash(&dir)
        .args([
            "add",
            "aws",
            "--login",
            "--username",
            "me@example.com",
            "--generate",
        ])
        .args(["--length", "32", "--no-symbols"])
        .assert()
        .success()
        .stdout("");
    let pw = out(&dir, &["get", "aws"]);
    assert_eq!(pw.len(), 32);
    assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()), "{pw}");
}

#[test]
fn two_factor_codes_from_logins() {
    let dir = init();
    github(&dir);
    stash(&dir)
        .args(["edit", "github", "--otp"])
        .write_stdin(format!("otpauth://totp/GitHub?secret={OTP_SECRET}"))
        .assert()
        .success();
    let code = out(&dir, &["otp", "github"]);
    assert!(
        code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()),
        "{code}"
    );
    // Same code through a field reference (unless the 30s window just rolled).
    let via_ref = out(&dir, &["get", "github#otp"]);
    let again = out(&dir, &["otp", "github"]);
    assert!(
        via_ref == code || via_ref == again,
        "{code} {via_ref} {again}"
    );

    stash(&dir)
        .args(["edit", "github", "--otp"])
        .write_stdin("not a secret")
        .assert()
        .failure()
        .stderr(predicate::str::contains("that isn't a 2FA secret"));
}

#[test]
fn show_hides_secrets_unless_revealed() {
    let dir = init();
    github(&dir);
    stash(&dir)
        .args(["edit", "github", "--notes"])
        .write_stdin("recovery codes in the safe")
        .assert()
        .success();

    let hidden = out(&dir, &["show", "github"]);
    assert!(hidden.contains("github  (login)"), "{hidden}");
    assert!(hidden.contains("octocat"), "{hidden}");
    assert!(hidden.contains("https://github.com"), "{hidden}");
    assert!(!hidden.contains("hunter2!"), "{hidden}");
    assert!(!hidden.contains("recovery codes"), "{hidden}");

    let shown = out(&dir, &["show", "github", "--reveal"]);
    assert!(shown.contains("hunter2!"), "{shown}");
    assert!(shown.contains("recovery codes in the safe"), "{shown}");
}

#[test]
fn notes_store_text() {
    let dir = init();
    stash(&dir)
        .args(["add", "notes/wifi", "--note"])
        .write_stdin("ssid: home\npass: correct horse\n")
        .assert()
        .success();
    assert_eq!(
        out(&dir, &["get", "notes/wifi"]),
        "ssid: home\npass: correct horse"
    );
    assert!(out(&dir, &["show", "notes/wifi"]).contains("(note)"));
}

#[test]
fn editing_a_secret_into_a_login_keeps_its_value_as_the_password() {
    let dir = init();
    stash(&dir)
        .args(["add", "db"])
        .write_stdin("s3cret")
        .assert()
        .success();
    stash(&dir)
        .args([
            "edit",
            "db",
            "--username",
            "admin",
            "--set",
            "host=db.internal",
        ])
        .assert()
        .success();
    assert_eq!(out(&dir, &["get", "db"]), "s3cret");
    assert_eq!(out(&dir, &["get", "db#username"]), "admin");
    assert_eq!(out(&dir, &["get", "db#host"]), "db.internal");

    stash(&dir)
        .args(["edit", "db", "--unset", "host"])
        .assert()
        .success();
    stash(&dir).args(["get", "db#host"]).assert().failure();
    stash(&dir)
        .args(["edit", "db", "--unset", "missing"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("has no field `missing`"));
    stash(&dir)
        .args(["edit", "db"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("nothing to change"));
}

#[test]
fn ls_long_summarizes_without_values() {
    let dir = init();
    github(&dir);
    stash(&dir)
        .args(["add", "api/key"])
        .write_stdin("tok")
        .assert()
        .success();
    let listing = out(&dir, &["ls", "--long"]);
    let lines: Vec<&str> = listing.lines().collect();
    assert!(lines[0].starts_with("NAME"), "{listing}");
    assert!(
        lines[1].starts_with("api/key") && lines[1].contains("secret"),
        "{listing}"
    );
    assert!(
        lines[2].contains("login") && lines[2].contains("octocat"),
        "{listing}"
    );
    assert!(!listing.contains("hunter2!") && !listing.contains("tok\n"));
}

#[test]
fn generate_prints_a_password() {
    let dir = init();
    let pw = out(&dir, &["generate", "--length", "40"]);
    assert_eq!(pw.len(), 40);
    stash(&dir)
        .args(["generate", "--length", "4"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("length must be 8–128"));
}

#[test]
fn login_flags_need_login_and_one_piped_secret() {
    let dir = init();
    stash(&dir)
        .args(["add", "x", "--username", "me"])
        .write_stdin("v")
        .assert()
        .failure()
        .stderr(predicate::str::contains("need --login"));
    stash(&dir)
        .args(["add", "x", "--login", "--otp"])
        .write_stdin("pw")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not both"));
}
