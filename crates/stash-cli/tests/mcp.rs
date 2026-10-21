//! End-to-end tests for `stash mcp`, driven over stdio like a real MCP client.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;

const PASSWORD: &str = "test-master-password";

/// A fake Touch ID helper. It logs every prompt (`unwrap: …` / `confirm: …`)
/// to `prompts`, and declines them all while a file named `deny` exists.
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
        for (name, value) in [
            ("github/token", "ghp_secret_123"),
            ("stripe/secret", "sk_live_456"),
        ] {
            f.cli()
                .args(["add", name])
                .write_stdin(value)
                .assert()
                .success();
        }
        f
    }

    fn base(&self) -> Command {
        let mut cmd = Command::cargo_bin("stash").unwrap();
        // A fixed agent list, so AI agents running on this machine don't pause sessions.
        cmd.env("STASH_AI_AGENTS", "stash-test-agent");
        cmd.env("STASH_VAULT", self.dir.path().join("vault.db"))
            .env("STASH_AGENT_SOCK", self.dir.path().join("agent.sock"))
            .env("STASH_TOUCHID_HELPER", &self.helper)
            .env_remove("STASH_SESSION_TIMEOUT");
        cmd
    }

    /// The CLI with the master password, for setup.
    fn cli(&self) -> Command {
        let mut cmd = self.base();
        cmd.env("STASH_PASSWORD", PASSWORD);
        cmd
    }

    /// Run `stash mcp <args>` with these requests; return the responses by id.
    fn mcp(&self, args: &[&str], calls: &[Value]) -> Vec<Value> {
        let mut input = String::new();
        let mut push = |v: Value| {
            input.push_str(&v.to_string());
            input.push('\n');
        };
        push(
            json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mcp-test", "version": "1"}
            }}),
        );
        push(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        for (i, call) in calls.iter().enumerate() {
            push(json!({"jsonrpc": "2.0", "id": i + 1, "method": "tools/call", "params": call}));
        }
        let out = self
            .base()
            .env_remove("STASH_PASSWORD")
            .arg("mcp")
            .args(args)
            .write_stdin(input)
            .timeout(std::time::Duration::from_secs(30))
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let responses: Vec<Value> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).expect("stdout must only carry JSON-RPC"))
            .collect();
        assert_eq!(responses.len(), calls.len() + 1, "{responses:#?}");
        assert_eq!(responses[0]["result"]["serverInfo"]["name"], "stash");
        responses[1..].iter().map(|r| r["result"].clone()).collect()
    }

    /// Prompts without their "(requested via …)" ending, which names the
    /// test runner and is checked on its own below.
    fn prompts(&self) -> Vec<String> {
        self.raw_prompts()
            .into_iter()
            .map(|p| match p.find(" (requested via ") {
                Some(i) => p[..i].to_owned(),
                None => p,
            })
            .collect()
    }

    fn raw_prompts(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.path().join("prompts"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The audit log, decrypted by `stash audit --json`. (The file itself
    /// is sealed: it never shows names, commands, or sites.)
    fn audit_log(&self) -> String {
        let raw = std::fs::read_to_string(self.dir.path().join("audit.log")).unwrap_or_default();
        assert!(
            !raw.contains("outcome"),
            "the audit log isn't sealed: {raw}"
        );
        let out = self
            .cli()
            .args(["audit", "--json", "-n", "100000"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        String::from_utf8(out).unwrap()
    }
}

fn text(result: &Value) -> &str {
    result["content"][0]["text"].as_str().unwrap()
}

fn run_call(command: &[&str], env: Value) -> Value {
    json!({"name": "run_with_secrets", "arguments": {"command": command, "env": env}})
}

#[test]
fn agents_run_commands_with_secrets_they_never_see() {
    let f = Fixture::new();
    let results = f.mcp(
        &["--allow", "github/*"],
        &[
            json!({"name": "list_secrets", "arguments": {}}),
            run_call(
                &["sh", "-c", r#"echo "token=$T port=$PORT"; exit 3"#],
                json!({"T": "stash://github/token", "PORT": "3000"}),
            ),
            run_call(
                &["sh", "-c", r#"test "$T" = ghp_secret_123"#],
                json!({"T": "stash://github/token"}),
            ),
        ],
    );

    // Only allowed names are listed.
    assert_eq!(text(&results[0]), "github/token");
    // The command got the real value; the agent got it masked.
    let out = text(&results[1]);
    assert!(
        out.contains("token=<concealed by stash> port=3000"),
        "{out}"
    );
    assert!(out.starts_with("exit code 3"), "{out}");
    assert!(!out.contains("ghp_secret_123"));
    assert_eq!(results[1]["structuredContent"]["exit_code"], 3);
    assert_eq!(results[2]["structuredContent"]["exit_code"], 0);

    // One unlock for the listing, then one approval per run, each saying
    // exactly what it's for.
    assert_eq!(
        f.prompts(),
        [
            "unwrap: let mcp-test list your secret names",
            "confirm: let mcp-test run `sh -c 'echo \"token=$T port=$PORT\"; exit 3'` with github/token, for up to 120s",
            "confirm: let mcp-test run `sh -c 'test \"$T\" = ghp_secret_123'` with github/token, for up to 120s",
        ]
    );
}

#[test]
fn the_unlock_prompt_counts_as_approval_for_the_first_request() {
    let f = Fixture::new();
    f.mcp(
        &[],
        &[run_call(&["true"], json!({"T": "stash://github/token"}))],
    );
    assert_eq!(
        f.prompts(),
        ["unwrap: let mcp-test run `true` with github/token, for up to 120s"]
    );
}

#[test]
fn declined_requests_never_run() {
    let f = Fixture::new();
    std::fs::write(f.dir.path().join("deny"), "").unwrap();
    let marker = f.dir.path().join("ran");
    let results = f.mcp(
        &[],
        &[run_call(
            &["touch", marker.to_str().unwrap()],
            json!({"T": "stash://github/token"}),
        )],
    );
    assert_eq!(results[0]["isError"], true);
    assert!(
        text(&results[0]).contains("declined"),
        "{}",
        text(&results[0])
    );
    assert!(!marker.exists(), "a declined command must not run");
    assert!(f.audit_log().contains(r#""outcome":"denied""#));
}

#[test]
fn secrets_outside_the_allowlist_are_blocked_without_a_prompt() {
    let f = Fixture::new();
    let results = f.mcp(
        &["--allow", "github/*"],
        &[run_call(&["true"], json!({"K": "stash://stripe/secret"}))],
    );
    assert_eq!(results[0]["isError"], true);
    assert!(text(&results[0]).contains("not allowed for AI agents: stripe/secret"));
    assert!(f.prompts().is_empty());
    assert!(f.audit_log().contains(r#""outcome":"blocked""#));
}

#[test]
fn revealing_values_is_off_unless_allowed() {
    let f = Fixture::new();
    let reveal = json!({"name": "request_secret", "arguments": {"name": "github/token"}});

    let results = f.mcp(&[], std::slice::from_ref(&reveal));
    assert_eq!(results[0]["isError"], true);
    assert!(text(&results[0]).contains("turned off"));
    assert!(f.prompts().is_empty());

    let results = f.mcp(&["--allow-reveal"], &[reveal]);
    assert_eq!(text(&results[0]), "ghp_secret_123");
    assert_eq!(
        f.prompts(),
        ["unwrap: let mcp-test see the value of github/token"]
    );
}

#[test]
fn commands_without_secrets_need_no_unlock_and_timeouts_kill_them() {
    let f = Fixture::new();
    let started = std::time::Instant::now();
    let results = f.mcp(
        &[],
        &[
            run_call(&["echo", "hello"], json!({})),
            json!({"name": "run_with_secrets", "arguments": {
                "command": ["sh", "-c", "sleep 20"], "timeout_seconds": 1
            }}),
        ],
    );
    assert!(text(&results[0]).contains("hello"));
    assert_eq!(results[1]["structuredContent"]["timed_out"], true);
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert!(f.prompts().is_empty());
}

#[test]
fn processes_a_command_leaves_running_are_stopped() {
    let f = Fixture::new();
    let pids = f.dir.path().join("pids");
    // A long-running program that isn't one of macOS's own (whose
    // environment macOS hides): `stash clipboard-clear` waits 30s.
    let waiter = format!(
        "{} clipboard-clear --after 30 </dev/null",
        assert_cmd::cargo::cargo_bin("stash").display()
    );
    // One left in the background, one detached into its own session (as
    // `setsid` or a double fork would), both holding the secret.
    let script = format!(
        r#"{waiter} & echo $! >> {p}
perl -e 'use POSIX; exit if fork; POSIX::setsid(); open my $f, ">>", shift; print $f "$$\n"; close $f; exec @ARGV' {p} sh -c 'exec {waiter}'
sleep 0.5; echo started"#,
        p = pids.display()
    );
    let results = f.mcp(
        &[],
        &[run_call(
            &["sh", "-c", &script],
            json!({"T": "stash://github/token"}),
        )],
    );
    let result = &results[0];
    assert_eq!(result["structuredContent"]["exit_code"], 0, "{result}");
    assert_eq!(
        result["structuredContent"]["stopped_background"], 2,
        "{result}"
    );
    assert!(text(&results[0]).contains("stopped 2 background process(es)"));
    let pids = std::fs::read_to_string(&pids).unwrap();
    assert_eq!(pids.lines().count(), 2);
    for pid in pids.lines() {
        let pid: i32 = pid.trim().parse().unwrap();
        // Give launchd/init a moment to reap it.
        let gone = (0..50).any(|_| {
            // SAFETY: signal 0 only checks whether the process exists.
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            if alive {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            !alive
        });
        assert!(gone, "process {pid} is still running");
    }
}

#[test]
fn the_audit_log_records_requests_but_never_values() {
    let f = Fixture::new();
    f.mcp(
        &[],
        &[run_call(
            &["sh", "-c", "echo $T"],
            json!({"T": "stash://github/token"}),
        )],
    );
    let log = f.audit_log();
    assert!(log.contains(r#""client":"mcp-test""#), "{log}");
    assert!(log.contains(r#""secrets":["github/token"]"#), "{log}");
    assert!(
        !log.contains("ghp_secret_123"),
        "values must never be logged"
    );

    let shown = f
        .cli()
        .arg("audit")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let shown = String::from_utf8(shown).unwrap();
    assert!(shown.contains("mcp-test"), "{shown}");
    assert!(shown.contains("run_with_secrets"), "{shown}");
    assert!(shown.contains("[github/token]"), "{shown}");

    // New keys: the history moves with them.
    f.cli().arg("rekey").assert().success();
    assert!(f.audit_log().contains(r#""secrets":["github/token"]"#));
}

#[test]
fn the_mcp_server_never_creates_a_shell_session() {
    let f = Fixture::new();
    f.mcp(&[], &[json!({"name": "list_secrets", "arguments": {}})]);
    assert!(!f.dir.path().join("agent.sock").exists());
}

#[test]
fn missing_references_fail_before_any_approval_prompt() {
    let f = Fixture::new();
    let results = f.mcp(
        &[],
        &[
            json!({"name": "list_secrets", "arguments": {}}),
            run_call(&["true"], json!({"T": "stash://github/token#nope"})),
            run_call(&["true"], json!({"T": "stash://missing"})),
        ],
    );
    for r in &results[1..] {
        assert_eq!(r["isError"], true, "{r}");
    }
    assert!(text(&results[1]).contains("has no field `nope`"));
    assert!(text(&results[2]).contains("no secret named `missing`"));
    // Only the unlock for list_secrets: no approval was asked for either run.
    assert_eq!(f.prompts().len(), 1, "{:?}", f.prompts());
}

#[test]
fn payment_cards_are_off_limits_to_agents_unless_allowed() {
    let f = Fixture::new();
    f.cli()
        .args(["add", "cards/visa", "--card"])
        .write_stdin("4242424242424242\n123\n")
        .assert()
        .success();
    let use_card = run_call(&["true"], json!({"N": "stash://cards/visa"}));
    let results = f.mcp(
        &[],
        &[
            json!({"name": "list_secrets", "arguments": {}}),
            use_card.clone(),
        ],
    );
    assert!(
        !text(&results[0]).contains("cards/visa"),
        "cards aren't listed"
    );
    assert_eq!(results[1]["isError"], true);
    assert!(text(&results[1]).contains("payment card or bank account"));
    assert!(f.audit_log().contains(r#""outcome":"blocked""#));
    assert!(
        !f.prompts().iter().any(|p| p.starts_with("confirm:")),
        "no approval was ever requested: {:?}",
        f.prompts()
    );

    let results = f.mcp(&["--allow-payments"], &[use_card]);
    assert!(
        results[0]["isError"].is_null() || results[0]["isError"] == false,
        "{}",
        results[0]
    );
}

#[test]
fn prompts_name_the_real_launcher_and_risky_flags() {
    let f = Fixture::new();
    f.mcp(
        &["--allow-reveal"],
        &[json!({"name": "list_secrets", "arguments": {}})],
    );
    let prompt = &f.raw_prompts()[0];
    // The client calls itself "mcp-test"; the kernel says who really
    // started the server.
    assert!(prompt.contains(" (requested via "), "{prompt}");
    assert!(prompt.ends_with("; --allow-reveal on)"), "{prompt}");
}

#[test]
fn no_approval_needs_the_password_in_the_environment() {
    let f = Fixture::new();
    f.base()
        .args(["mcp", "--no-approval"])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicates::str::contains("only for headless use"));
}
