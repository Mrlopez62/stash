//! Attacks from other programs running as you, and what stops them.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use assert_cmd::Command;
use tempfile::TempDir;

const PASSWORD: &str = "test-master-password";

fn fake_touch_id(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("stash-touchid");
    std::fs::write(
        &path,
        "#!/bin/sh\ncase \"$1\" in\n  available) exit 0 ;;\n  wrap) read k; echo \"fake:$k\" ;;\n  \
         unwrap) read b; echo \"${b#fake:}\" ;;\n  confirm) exit 0 ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn stash(dir: &Path, helper: &Path) -> Command {
    let mut cmd = Command::cargo_bin("stash").unwrap();
    // A fixed agent list, so AI agents running on this machine don't pause sessions.
    cmd.env("STASH_AI_AGENTS", "stash-test-agent");
    cmd.env("STASH_VAULT", dir.join("vault.db"))
        .env("STASH_AGENT_SOCK", dir.join("agent.sock"))
        .env("STASH_TOUCHID_HELPER", helper)
        .env_remove("STASH_SESSION_TIMEOUT");
    cmd
}

#[test]
fn an_impostor_agent_never_gets_the_vault_key() {
    let dir = TempDir::new().unwrap();
    let helper = fake_touch_id(dir.path());
    stash(dir.path(), &helper)
        .env("STASH_PASSWORD", PASSWORD)
        .arg("init")
        .assert()
        .success();
    stash(dir.path(), &helper)
        .env("STASH_PASSWORD", PASSWORD)
        .args(["touchid", "enable"])
        .assert()
        .success();
    stash(dir.path(), &helper)
        .env("STASH_PASSWORD", PASSWORD)
        .args(["add", "demo"])
        .write_stdin("value")
        .assert()
        .success();

    // A different program (this test) listening where the agent would,
    // answering exactly like it.
    let listener = UnixListener::bind(dir.path().join("agent.sock")).unwrap();
    let heard = Arc::new(Mutex::new(Vec::<String>::new()));
    let log = Arc::clone(&heard);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut line = String::new();
            if BufReader::new(&stream).read_line(&mut line).is_err() {
                continue;
            }
            let reply = match line.split(' ').next().unwrap_or("").trim() {
                "PING" => "PONG",
                "PUT" => "OK",
                _ => "NONE",
            };
            log.lock().unwrap().push(line.trim().to_owned());
            let _ = (&stream).write_all(format!("{reply}\n").as_bytes());
        }
    });

    let out = stash(dir.path(), &helper)
        .env_remove("STASH_PASSWORD")
        .args(["get", "demo"])
        .output()
        .unwrap();
    assert!(out.status.success(), "the unlock itself still works");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "value");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not handing it your key"), "{stderr}");
    let heard = heard.lock().unwrap();
    assert!(
        heard.iter().all(|l| !l.starts_with("PUT")),
        "the impostor was sent a key: {heard:?}"
    );
}
