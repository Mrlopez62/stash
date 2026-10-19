//! End-to-end tests for browser autofill: `stash browser install`, and
//! `stash native-host` driven over native messaging like a browser does.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;

const PASSWORD: &str = "test-master-password";
const CHROME_ORIGIN: &str = "chrome-extension://jddlnapigcddjhnbbjblfjdgfplocfef/";

/// The fake Touch ID helper from the MCP tests: logs prompts, declines them
/// while `deny` exists.
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
        f.cli().arg("init").assert().success();
        f.cli().args(["touchid", "enable"]).assert().success();
        f.cli()
            .args([
                "add",
                "github",
                "--login",
                "--username",
                "octocat",
                "--url",
                "https://github.com",
            ])
            .write_stdin("hunter2!\n")
            .assert()
            .success();
        f.cli()
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
        f
    }

    fn cli(&self) -> Command {
        let mut cmd = Command::cargo_bin("stash").unwrap();
        cmd.env("STASH_VAULT", self.dir.path().join("vault.db"))
            .env("STASH_AGENT_SOCK", self.dir.path().join("agent.sock"))
            .env("STASH_TOUCHID_HELPER", &self.helper)
            .env("STASH_PASSWORD", PASSWORD)
            .env("STASH_SESSION_TIMEOUT", "0")
            .env("HOME", self.dir.path());
        cmd
    }

    /// Send requests to `stash native-host` as the browser would; return
    /// the replies.
    fn host(&self, args: &[&str], requests: &[Value]) -> (Vec<Value>, String) {
        let mut child = Process::new(assert_cmd::cargo::cargo_bin("stash"))
            .arg("native-host")
            .args(args)
            .env("STASH_VAULT", self.dir.path().join("vault.db"))
            .env("STASH_TOUCHID_HELPER", &self.helper)
            .env_remove("STASH_PASSWORD")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        for r in requests {
            let body = serde_json::to_vec(r).unwrap();
            stdin.write_all(&(body.len() as u32).to_ne_bytes()).unwrap();
            stdin.write_all(&body).unwrap();
        }
        drop(stdin);
        let out = child.wait_with_output().unwrap();
        let mut replies = Vec::new();
        let mut rest = &out.stdout[..];
        while rest.len() >= 4 {
            let len = u32::from_ne_bytes(rest[..4].try_into().unwrap()) as usize;
            replies.push(serde_json::from_slice(&rest[4..4 + len]).unwrap());
            rest = &rest[4 + len..];
        }
        (replies, String::from_utf8_lossy(&out.stderr).into_owned())
    }

    fn prompts(&self) -> Vec<String> {
        let mut s = String::new();
        if let Ok(mut f) = std::fs::File::open(self.dir.path().join("prompts")) {
            f.read_to_string(&mut s).unwrap();
        }
        s.lines().map(str::to_owned).collect()
    }
}

#[test]
fn refuses_callers_that_arent_the_stash_extension() {
    let f = Fixture::new();
    let (replies, stderr) = f.host(
        &["chrome-extension://evil/"],
        &[json!({ "id": 1, "type": "status" })],
    );
    assert!(replies.is_empty());
    assert!(
        stderr.contains("only answers the stash browser extension"),
        "{stderr}"
    );
}

#[test]
fn unlocks_suggests_and_fills_a_login() {
    let f = Fixture::new();
    let url = "https://github.com/login";
    let (r, _) = f.host(
        &[CHROME_ORIGIN],
        &[
            json!({ "id": 1, "type": "suggest", "url": url }),
            json!({ "id": 2, "type": "unlock", "url": url }),
            json!({ "id": 3, "type": "fill", "url": url, "name": "github", "kind": "login" }),
            json!({ "id": 4, "type": "fill", "url": "https://github.com.evil.io/", "name": "github", "kind": "login" }),
        ],
    );
    assert_eq!(r[0]["locked"], true);
    assert_eq!(r[1]["logins"][0]["name"], "github");
    assert_eq!(r[1]["payments"][0]["summary"], "Visa •••• 4242 · 08/27");
    assert_eq!(r[2]["password"], "hunter2!");
    assert_eq!(r[3]["ok"], false, "lookalike site: {}", r[3]);
    let prompts = f.prompts();
    assert_eq!(
        prompts.len(),
        1,
        "one unlock covers login fills: {prompts:?}"
    );
    assert!(prompts[0].starts_with("unwrap: unlock stash for autofill in "));
    assert!(
        prompts[0]
            .ends_with(": logins on any site for the next 10 minutes, starting with github.com"),
        "the prompt says how far one unlock reaches: {prompts:?}"
    );
}

#[test]
fn every_card_fill_asks_touch_id_naming_the_site() {
    let f = Fixture::new();
    let fill = json!({ "id": 1, "type": "fill", "url": "https://shop.example/pay", "name": "cards/visa", "kind": "card" });
    let (r, _) = f.host(&[CHROME_ORIGIN], &[fill.clone(), fill]);
    assert_eq!(r[0]["number"], "4242424242424242");
    assert_eq!(r[1]["cvv"], "123");
    let prompts = f.prompts();
    assert_eq!(prompts.len(), 2, "{prompts:?}");
    assert!(
        prompts[0]
            .starts_with("unwrap: fill your payment details “cards/visa” on shop.example in ")
    );
    assert!(prompts[1].starts_with("confirm: fill Visa •••• 4242 · 08/27 on shop.example in "));

    std::fs::write(f.dir.path().join("deny"), "").unwrap();
    let (r, _) = f.host(
        &[CHROME_ORIGIN],
        &[json!({ "id": 1, "type": "fill", "url": "https://shop.example/", "name": "cards/visa", "kind": "card" })],
    );
    assert_eq!(r[0]["ok"], false);
    assert!(r[0].get("number").is_none());
    let log = std::fs::read_to_string(f.dir.path().join("audit.log")).unwrap();
    assert!(log.contains(r#""tool":"autofill""#) && log.contains(r#""outcome":"denied""#));
    assert!(!log.contains("4242424242424242") && !log.contains("hunter2"));
}

#[test]
fn install_registers_the_host_and_unpacks_the_extension() {
    let f = Fixture::new();
    let chrome = if cfg!(target_os = "macos") {
        "Library/Application Support/Google/Chrome"
    } else {
        ".config/google-chrome"
    };
    std::fs::create_dir_all(f.dir.path().join(chrome)).unwrap();
    f.cli().args(["browser", "install"]).assert().success();

    let manifest_path = f
        .dir
        .path()
        .join(chrome)
        .join("NativeMessagingHosts/dev.stash.autofill.json");
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["allowed_origins"], json!([CHROME_ORIGIN]));
    let launcher = PathBuf::from(manifest["path"].as_str().unwrap());
    let script = std::fs::read_to_string(&launcher).unwrap();
    assert!(script.contains("native-host \"$@\""), "{script}");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&launcher).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for browser in ["chrome", "firefox"] {
        let ext = f.dir.path().join("browser-extension").join(browser);
        assert!(ext.join("manifest.json").is_file(), "{browser}");
        assert!(ext.join("icons/icon-128.png").is_file(), "{browser}");
    }

    f.cli()
        .args(["browser", "status"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Google Chrome: connected"));
    f.cli().args(["browser", "uninstall"]).assert().success();
    f.cli()
        .args(["browser", "status"])
        .assert()
        .stdout(predicates::str::contains("Google Chrome: not connected"));
}

#[test]
fn saves_a_new_login_from_a_sign_in_after_one_unlock() {
    let f = Fixture::new();
    let url = "https://www.shop.example/login";
    let (r, _) = f.host(
        &[CHROME_ORIGIN],
        &[
            json!({ "id": 1, "type": "check_saved", "url": url, "username": "me@x.com", "password": "s3cret" }),
            json!({ "id": 2, "type": "save_login", "url": url, "username": "me@x.com", "password": "s3cret" }),
            json!({ "id": 3, "type": "check_saved", "url": url, "username": "me@x.com", "password": "s3cret" }),
        ],
    );
    assert_eq!(r[0]["state"], "locked");
    assert_eq!(
        (r[1]["name"].as_str(), r[1]["action"].as_str()),
        (Some("shop.example"), Some("created")),
        "{}",
        r[1]
    );
    assert_eq!(r[2]["state"], "same");
    let prompts = f.prompts();
    assert_eq!(prompts.len(), 1, "{prompts:?}");
    assert!(
        prompts[0].starts_with("unwrap: unlock stash to save your login for www.shop.example in ")
    );
    // It's a normal login now, with the site as its website.
    f.cli()
        .args(["get", "shop.example#website"])
        .assert()
        .success()
        .stdout(predicates::str::contains("https://www.shop.example"));
}
