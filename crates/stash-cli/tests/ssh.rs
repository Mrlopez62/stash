//! End-to-end tests for `stash ssh`: keys in the vault, and the agent
//! spoken to over its socket like `ssh` would.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use tempfile::TempDir;

const PASSWORD: &str = "test-master-password";

/// The same fake Touch ID helper as the MCP tests: logs prompts, declines
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
        f.cli().arg("init").assert().success();
        f.cli().args(["touchid", "enable"]).assert().success();
        f
    }

    fn cli(&self) -> Command {
        let mut cmd = Command::cargo_bin("stash").unwrap();
        cmd.env("STASH_VAULT", self.dir.path().join("vault.db"))
            .env("STASH_AGENT_SOCK", self.dir.path().join("agent.sock"))
            .env("STASH_TOUCHID_HELPER", &self.helper)
            .env("STASH_PASSWORD", PASSWORD)
            .env("STASH_SESSION_TIMEOUT", "0");
        cmd
    }

    fn generate(&self, name: &str) -> String {
        let out = self.cli().args(["ssh", "generate", name]).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    fn socket(&self) -> PathBuf {
        self.dir.path().join("ssh.sock")
    }

    /// The agent, unlocking through the fake Touch ID (no master password).
    // `Agent`'s Drop kills and waits for the child.
    #[allow(clippy::zombie_processes)]
    fn agent(&self) -> Agent {
        let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("stash"))
            .args(["ssh", "agent", "--socket"])
            .arg(self.socket())
            .env("STASH_VAULT", self.dir.path().join("vault.db"))
            .env("STASH_TOUCHID_HELPER", &self.helper)
            .env_remove("STASH_PASSWORD")
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if let Ok(stream) = UnixStream::connect(self.socket()) {
                return Agent { child, stream };
            }
            if start.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("agent didn't start");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn prompts(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.path().join("prompts"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

struct Agent {
    child: Child,
    stream: UnixStream,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn get_string(data: &mut &[u8]) -> Vec<u8> {
    let len = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
    let s = data[4..4 + len].to_vec();
    *data = &data[4 + len..];
    s
}

impl Agent {
    fn call(&mut self, message: &[u8]) -> Vec<u8> {
        let mut framed = (message.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(message);
        self.stream.write_all(&framed).unwrap();
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len).unwrap();
        let mut reply = vec![0u8; u32::from_be_bytes(len) as usize];
        self.stream.read_exact(&mut reply).unwrap();
        reply
    }

    /// (blob, comment) for each key the agent offers.
    fn identities(&mut self) -> Vec<(Vec<u8>, String)> {
        let reply = self.call(&[11]);
        assert_eq!(reply[0], 12);
        let mut rest = &reply[5..];
        let n = u32::from_be_bytes(reply[1..5].try_into().unwrap());
        (0..n)
            .map(|_| {
                let blob = get_string(&mut rest);
                (blob, String::from_utf8(get_string(&mut rest)).unwrap())
            })
            .collect()
    }

    fn sign(&mut self, blob: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        let mut m = vec![13];
        put_string(&mut m, blob);
        put_string(&mut m, data);
        m.extend_from_slice(&0u32.to_be_bytes());
        let reply = self.call(&m);
        (reply[0] == 14).then(|| reply[1..].to_vec())
    }
}

/// What `ssh` signs to log in as `user` (RFC 4252 §7).
fn login_data(user: &str) -> Vec<u8> {
    let mut d = Vec::new();
    put_string(&mut d, b"session");
    d.push(50);
    put_string(&mut d, user.as_bytes());
    put_string(&mut d, b"ssh-connection");
    put_string(&mut d, b"publickey");
    d
}

#[test]
fn generates_lists_and_prints_keys() {
    let f = Fixture::new();
    let public = f.generate("ssh/github");
    assert!(public.starts_with("ssh-ed25519 AAAA"), "{public}");
    assert!(
        public.ends_with(" ssh/github"),
        "the comment defaults to the name"
    );

    let out = f
        .cli()
        .args(["ssh", "public", "ssh/github"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), public);
    let out = f.cli().args(["ssh", "ls"]).output().unwrap();
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .contains("ssh/github\tEd25519 · SHA256:")
    );

    // It's an SSH key, not a login: no passwords or 2FA.
    f.cli()
        .args(["edit", "ssh/github", "--generate"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("is an SSH key"));
    f.cli()
        .args(["ssh", "generate", "ssh/github"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("already exists"));
}

#[test]
fn imports_ssh_keygen_files_and_refuses_other_kinds() {
    let f = Fixture::new();
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../stash-core/tests/data");
    f.cli()
        .args(["ssh", "import", "ssh/old"])
        .arg(data.join("ed25519"))
        .assert()
        .success();
    let out = f.cli().args(["ssh", "public", "ssh/old"]).output().unwrap();
    let expected = std::fs::read_to_string(data.join("ed25519.pub")).unwrap();
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        expected.trim()
    );

    f.cli()
        .args(["ssh", "import", "ssh/pub"])
        .arg(data.join("ed25519.pub"))
        .assert()
        .failure()
        .stderr(predicates::str::contains("that's a public key"));
    f.cli()
        .args(["add", "token"])
        .write_stdin("x")
        .assert()
        .success();
    f.cli()
        .args(["ssh", "public", "token"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("not an SSH key"));
}

#[test]
fn the_agent_asks_touch_id_for_every_signature() {
    let f = Fixture::new();
    f.generate("ssh/github");
    f.cli()
        .args(["add", "token"])
        .write_stdin("x")
        .assert()
        .success();
    let mut agent = f.agent();

    let keys = agent.identities();
    assert_eq!(keys.len(), 1, "only SSH keys are offered");
    assert_eq!(keys[0].1, "ssh/github");
    assert_eq!(
        f.prompts().len(),
        1,
        "listing unlocked once: {:?}",
        f.prompts()
    );
    assert!(f.prompts()[0].starts_with("unwrap: unlock stash to list SSH keys"));

    let blob = keys[0].0.clone();
    assert!(agent.sign(&blob, &login_data("git")).is_some());
    let prompts = f.prompts();
    assert_eq!(prompts.len(), 2, "{prompts:?}");
    assert!(
        prompts[1].starts_with("confirm: use SSH key “ssh/github” to log in as git, for "),
        "{prompts:?}"
    );

    // Listing again needs no prompt; a declined prompt signs nothing.
    agent.identities();
    std::fs::write(f.dir.path().join("deny"), "").unwrap();
    assert!(agent.sign(&blob, &login_data("git")).is_none());
    assert_eq!(f.prompts().len(), 3);

    // The audit log names the key and the outcome, never key material.
    let log = std::fs::read_to_string(f.dir.path().join("audit.log")).unwrap();
    assert!(log.contains(r#""tool":"ssh-sign""#));
    assert!(log.contains(r#""outcome":"approved""#));
    assert!(log.contains(r#""outcome":"denied""#));
    assert!(!log.contains("PRIVATE KEY"));
}

#[test]
fn a_locked_agent_unlocks_and_signs_with_one_prompt() {
    let f = Fixture::new();
    let public = f.generate("ssh/github");
    let mut agent = f.agent();
    // A blob from the public key line, as ssh would send it.
    let b64 = public.split_whitespace().nth(1).unwrap();
    let blob = base64_decode(b64);
    let mut sshsig = b"SSHSIG".to_vec();
    put_string(&mut sshsig, b"git");
    assert!(agent.sign(&blob, &sshsig).is_some());
    let prompts = f.prompts();
    assert_eq!(prompts.len(), 1, "{prompts:?}");
    assert!(
        prompts[0].starts_with("unwrap: unlock stash to list SSH keys"),
        "{prompts:?}"
    );
}

#[test]
fn ai_agents_never_get_ssh_private_keys() {
    let f = Fixture::new();
    f.generate("ssh/github");
    let mut input = String::new();
    for line in [
        r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_secrets","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"request_secret","arguments":{"name":"ssh/github"}}}"#,
    ] {
        input.push_str(line);
        input.push('\n');
    }
    let out = f
        .cli()
        .args(["mcp", "--allow-reveal", "--allow-payments", "--no-approval"])
        .write_stdin(input)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(!lines[1].contains("ssh/github"), "not listed: {}", lines[1]);
    assert!(lines[2].contains("is an SSH key"), "{}", lines[2]);
    assert!(!stdout.contains("PRIVATE KEY"));
}

fn base64_decode(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.bytes().filter(|&c| c != b'=') {
        bits = (bits << 6) | ALPHABET.iter().position(|&a| a == c).unwrap() as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out
}
