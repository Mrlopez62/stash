//! End-to-end tests for logins, notes, editing, showing, and generating.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const PASSWORD: &str = "test-master-password";
const OTP_SECRET: &str = "JBSWY3DPEHPK3PXP";

fn stash(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("stash").unwrap();
    // A fixed agent list, so AI agents running on this machine don't pause sessions.
    cmd.env("STASH_AI_AGENTS", "stash-test-agent");
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

// ---- regressions from the v0.6 security review ----

#[test]
fn notes_added_to_a_plain_secret_are_kept() {
    let dir = init();
    stash(&dir)
        .args(["add", "api/key"])
        .write_stdin("tok")
        .assert()
        .success();
    stash(&dir)
        .args(["edit", "api/key", "--notes"])
        .write_stdin("rotate every 90 days")
        .assert()
        .success();
    let shown = out(&dir, &["show", "api/key", "--reveal"]);
    assert!(shown.contains("rotate every 90 days"), "{shown}");
    assert_eq!(out(&dir, &["get", "api/key"]), "tok");
}

#[test]
fn set_refuses_secret_fields_so_they_stay_out_of_shell_history() {
    let dir = init();
    github(&dir);
    for label in ["password", "Password", "one-time password", "otp", "notes"] {
        stash(&dir)
            .args(["edit", "github", "--set", &format!("{label}=leaked")])
            .assert()
            .failure()
            .stderr(predicate::str::contains("shell history"));
    }
    // Nothing was changed.
    assert_eq!(out(&dir, &["get", "github"]), "hunter2!");

    // Visible fields keep their type: the website is still a URL.
    stash(&dir)
        .args(["edit", "github", "--set", "website=https://github.example"])
        .assert()
        .success();
    let listing = out(&dir, &["ls", "--long"]);
    assert!(listing.contains("https://github.example"), "{listing}");
}

#[test]
fn a_secrets_only_value_cant_be_unset_and_empty_input_is_refused() {
    let dir = init();
    stash(&dir)
        .args(["add", "api/key"])
        .write_stdin("tok")
        .assert()
        .success();
    stash(&dir)
        .args(["edit", "api/key", "--unset", "value"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("stash rm api/key"));
    assert_eq!(out(&dir, &["get", "api/key"]), "tok");

    stash(&dir)
        .args(["add", "empty", "--login"])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("value is empty"));
    stash(&dir)
        .args(["add", "empty"])
        .write_stdin("\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("value is empty"));
}

#[test]
fn existing_items_are_reported_before_asking_for_a_password() {
    let dir = init();
    github(&dir);
    // No stdin at all: if it tried to read a password first, it would fail
    // with "value is empty" instead.
    stash(&dir)
        .args(["add", "github", "--login"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("github already exists"));
}

#[test]
fn short_2fa_secrets_from_older_versions_keep_working() {
    let dir = init();
    // 15 base32 characters (75 bits): accepted by v0.5, too short for new input.
    stash(&dir)
        .args(["add", "old/2fa"])
        .write_stdin("JBSWY3DPEHPK3PX")
        .assert()
        .success();
    let code = out(&dir, &["otp", "old/2fa"]);
    assert_eq!(code.len(), 6, "{code}");

    github(&dir);
    stash(&dir)
        .args(["edit", "github", "--otp"])
        .write_stdin("JBSWY3DPEHPK3PX")
        .assert()
        .failure()
        .stderr(predicate::str::contains("too short"));
}

#[test]
fn changing_a_secrets_value_or_making_it_a_login_keeps_its_notes() {
    // Regression from the fix re-check: `edit --password` on a secret used
    // to replace the whole item, wiping its notes.
    let dir = init();
    stash(&dir)
        .args(["add", "api/key"])
        .write_stdin("old")
        .assert()
        .success();
    stash(&dir)
        .args(["edit", "api/key", "--notes"])
        .write_stdin("rotate every 90 days")
        .assert()
        .success();
    stash(&dir)
        .args(["edit", "api/key", "--password"])
        .write_stdin("new")
        .assert()
        .success();
    assert_eq!(out(&dir, &["get", "api/key"]), "new");
    assert!(out(&dir, &["show", "api/key", "--reveal"]).contains("rotate every 90 days"));

    stash(&dir)
        .args(["edit", "api/key", "--username", "svc"])
        .assert()
        .success();
    let shown = out(&dir, &["show", "api/key", "--reveal"]);
    assert!(shown.contains("(login)"), "{shown}");
    assert!(shown.contains("rotate every 90 days"), "{shown}");
    assert_eq!(out(&dir, &["get", "api/key"]), "new");
}

#[test]
fn set_refuses_labels_that_look_like_secrets() {
    let dir = init();
    github(&dir);
    for label in ["token", "API key", "client_secret", "pin"] {
        stash(&dir)
            .args(["edit", "github", "--set", &format!("{label}=leaked")])
            .assert()
            .failure()
            .stderr(predicate::str::contains("looks like a secret"));
    }
}

#[test]
fn custom_fields_on_a_secret_keep_it_a_secret() {
    // Regression (PR #9 review): `--set` used to turn an API key into a
    // "login" whose value was relabeled "password".
    let dir = init();
    stash(&dir)
        .args(["add", "api/key"])
        .write_stdin("sk_live_123")
        .assert()
        .success();
    stash(&dir)
        .args(["edit", "api/key", "--set", "scope=read-only"])
        .assert()
        .success();
    let shown = out(&dir, &["show", "api/key"]);
    assert!(shown.starts_with("api/key  (secret)"), "{shown}");
    assert_eq!(out(&dir, &["get", "api/key"]), "sk_live_123");
    assert_eq!(out(&dir, &["get", "api/key#scope"]), "read-only");

    // Its value can't be removed, even with other fields present: the next
    // field would silently become the secret.
    stash(&dir)
        .args(["edit", "api/key", "--unset", "value"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("stash rm api/key"));
    stash(&dir)
        .args(["edit", "api/key", "--unset", "scope"])
        .assert()
        .success();
    assert_eq!(out(&dir, &["get", "api/key"]), "sk_live_123");
}

// ---- payment cards and bank accounts ----

fn visa(dir: &TempDir) {
    stash(dir)
        .args([
            "add",
            "cards/visa",
            "--card",
            "--cardholder",
            "Samus Aran",
            "--expiry",
            "8/2027",
        ])
        .write_stdin("4242 4242 4242 4242\n123\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("Visa •••• 4242 · 08/27"));
}

#[test]
fn cards_store_and_reference_their_fields() {
    let dir = init();
    visa(&dir);
    assert_eq!(out(&dir, &["get", "cards/visa"]), "4242424242424242");
    assert_eq!(out(&dir, &["get", "cards/visa#cvv"]), "123");
    assert_eq!(out(&dir, &["get", "cards/visa#expiry"]), "08/27");
    assert_eq!(out(&dir, &["get", "cards/visa#name"]), "Samus Aran");

    // Show and list reveal only the last four digits.
    let shown = out(&dir, &["show", "cards/visa"]);
    assert!(shown.contains("•••• 4242"), "{shown}");
    assert!(
        !shown.contains("4242424242424242") && !shown.contains("123\n"),
        "{shown}"
    );
    let revealed = out(&dir, &["show", "cards/visa", "--reveal"]);
    assert!(revealed.contains("4242 4242 4242 4242"), "{revealed}");
    let listing = out(&dir, &["ls", "--long"]);
    assert!(
        listing.contains("card") && listing.contains("Visa •••• 4242"),
        "{listing}"
    );
}

#[test]
fn mistyped_cards_are_refused_before_saving() {
    let dir = init();
    stash(&dir)
        .args(["add", "cards/typo", "--card"])
        .write_stdin("4242 4242 4242 4241\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("typo"));
    stash(&dir)
        .args(["add", "cards/amex", "--card", "--expiry", "13/27"])
        .write_stdin("378282246310005\n1234\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("MM/YY"));
    stash(&dir).args(["get", "cards/typo"]).assert().failure();
}

#[test]
fn card_numbers_can_only_change_through_a_prompt() {
    let dir = init();
    visa(&dir);
    for label in ["number", "cvv", "security code"] {
        stash(&dir)
            .args([
                "edit",
                "cards/visa",
                "--set",
                &format!("{label}=4111111111111111"),
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("shell history"));
    }
    stash(&dir)
        .args(["edit", "cards/visa", "--password"])
        .write_stdin("5555 5555 5555 4444")
        .assert()
        .success();
    assert_eq!(out(&dir, &["get", "cards/visa"]), "5555555555554444");
    stash(&dir)
        .args(["edit", "cards/visa", "--password"])
        .write_stdin("5555 5555 5555 4445")
        .assert()
        .failure()
        .stderr(predicate::str::contains("typo"));
    stash(&dir)
        .args(["edit", "cards/visa", "--username", "me"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no username"));
}

#[test]
fn bank_accounts_validate_routing_numbers_and_ibans() {
    let dir = init();
    stash(&dir)
        .args(["add", "banks/chase", "--bank", "--bank-name", "Chase"])
        .args(["--routing", "021000021", "--account-type", "checking"])
        .write_stdin("000123456789\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("Chase · Checking •••• 6789"));
    assert_eq!(out(&dir, &["get", "banks/chase"]), "000123456789");
    assert_eq!(out(&dir, &["get", "banks/chase#routing"]), "021000021");

    stash(&dir)
        .args(["add", "banks/eu", "--bank", "--iban"])
        .write_stdin("\nGB82 WEST 1234 5698 7654 32\n")
        .assert()
        .success();
    assert_eq!(out(&dir, &["get", "banks/eu"]), "GB82WEST12345698765432");

    stash(&dir)
        .args(["add", "banks/typo", "--bank", "--routing", "021000022"])
        .write_stdin("123\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("routing number"));
}

const CHROME_CSV: &str = "name,url,username,password,note\n\
GitHub,https://github.com/login,octocat,gh-pass-1,\n\
,https://www.example.com/,me@example.com,ex-pass,remember me\n";

#[test]
fn imports_a_chrome_export_without_overwriting_anything() {
    let dir = init();
    let file = dir.path().join("Chrome Passwords.csv");
    std::fs::write(&file, CHROME_CSV).unwrap();

    // A dry run lists names and kinds, never values, and changes nothing.
    stash(&dir)
        .args(["import", "--dry-run"])
        .arg(&file)
        .assert()
        .success()
        .stdout(predicate::str::contains("github").and(predicate::str::contains("example.com")))
        .stdout(predicate::str::contains("gh-pass-1").not())
        .stderr(predicate::str::contains(
            "Found 2 items in this Chrome, Brave, Edge, or Arc export",
        ));
    assert!(out(&dir, &["ls"]).trim().is_empty());

    stash(&dir)
        .arg("import")
        .arg(&file)
        .assert()
        .success()
        .stderr(predicate::str::contains("Imported 2 items: 2 logins"));
    assert_eq!(out(&dir, &["get", "github"]), "gh-pass-1");
    assert_eq!(
        out(&dir, &["get", "example.com#username"]),
        "me@example.com"
    );
    // Not asked to delete (not a terminal), and not deleted.
    assert!(file.exists());

    // Importing again changes nothing; a different item with a taken name
    // gets a new name instead of replacing the old one.
    std::fs::write(
        &file,
        format!("{CHROME_CSV}GitHub,https://github.com/,someone-else,other-pass,\n"),
    )
    .unwrap();
    stash(&dir)
        .args(["import", "--delete-file"])
        .arg(&file)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "2 already in your vault, unchanged",
        ))
        .stderr(predicate::str::contains(
            "github was taken, so it's github-2",
        ));
    assert_eq!(out(&dir, &["get", "github"]), "gh-pass-1");
    assert_eq!(out(&dir, &["get", "github-2"]), "other-pass");
    assert!(!file.exists(), "--delete-file deletes the export");

    // The same file again, clash included: nothing new (no github-3).
    std::fs::write(
        &file,
        format!("{CHROME_CSV}GitHub,https://github.com/,someone-else,other-pass,\n"),
    )
    .unwrap();
    stash(&dir)
        .arg("import")
        .arg(&file)
        .assert()
        .success()
        .stderr(predicate::str::contains("Imported 0 items"))
        .stderr(predicate::str::contains(
            "3 already in your vault, unchanged",
        ));
    assert!(!out(&dir, &["ls"]).contains("github-3"));
}

#[test]
fn imports_cards_and_lists_what_it_skips() {
    let dir = init();
    let file = dir.path().join("bitwarden.json");
    std::fs::write(
        &file,
        r#"{"encrypted": false, "folders": [], "items": [
          {"type": 3, "name": "Visa", "card": {"cardholderName": "Samus Aran",
           "number": "4242424242424242", "expMonth": "8", "expYear": "2027", "code": "123"}},
          {"type": 3, "name": "Typo", "card": {"number": "4242424242424241"}}]}"#,
    )
    .unwrap();
    stash(&dir)
        .arg("import")
        .arg(&file)
        .assert()
        .success()
        .stderr(predicate::str::contains("skipping “Typo”"))
        .stderr(predicate::str::contains("Imported 1 item: 1 card"));
    assert_eq!(out(&dir, &["get", "cards/visa"]), "4242424242424242");

    std::fs::write(dir.path().join("junk.csv"), "a,b\n1,2\n").unwrap();
    stash(&dir)
        .arg("import")
        .arg(dir.path().join("junk.csv"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "doesn't look like a password export",
        ));
}

#[test]
fn exports_a_payments_only_vault_for_the_phone() {
    let dir = init();
    let phone = dir.path().join("phone.stashvault");
    // No cards yet: nothing to export.
    stash(&dir)
        .args(["export", "--phone"])
        .arg(&phone)
        .env("STASH_NEW_PASSWORD", "phone-password")
        .assert()
        .failure()
        .stderr(predicate::str::contains("no cards or bank accounts"));

    github(&dir);
    stash(&dir)
        .args(["add", "cards/visa", "--card", "--expiry", "8/2027"])
        .write_stdin("4242 4242 4242 4242\n123\n")
        .assert()
        .success();
    stash(&dir)
        .args(["export", "--phone"])
        .arg(dir.path().join("phone.zip"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(".stashvault"));
    stash(&dir)
        .args(["export", "--phone"])
        .arg(&phone)
        .env("STASH_NEW_PASSWORD", "phone-password")
        .assert()
        .success()
        .stderr(predicate::str::contains("1 card and 0 bank accounts"));

    // The phone vault opens with its own password and holds only the card.
    let open_phone = || {
        let mut cmd = stash(&dir);
        cmd.env("STASH_VAULT", &phone)
            .env("STASH_PASSWORD", "phone-password");
        cmd
    };
    let listed = String::from_utf8(
        open_phone()
            .arg("ls")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert_eq!(listed.trim(), "cards/visa");
    let number = open_phone().args(["get", "cards/visa"]).assert().success();
    assert_eq!(number.get_output().stdout, b"4242424242424242");
    let mut wrong = stash(&dir);
    wrong
        .env("STASH_VAULT", &phone)
        .arg("ls")
        .assert()
        .failure();

    // It isn't replaced without --force.
    stash(&dir)
        .args(["export", "--phone"])
        .arg(&phone)
        .env("STASH_NEW_PASSWORD", "phone-password")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--force"));
}
