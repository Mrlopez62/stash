use assert_cmd::Command;
use assert_cmd::cargo::CommandCargoExt;
use predicates::prelude::*;
use tempfile::TempDir;

const PASSWORD: &str = "test-master-password";

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
/// Each unwrap (i.e. each Touch ID prompt) appends its reason to `unwraps`,
/// and is declined while `deny` exists.
fn fake_touch_id(dir: &TempDir) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.path().join("stash-touchid");
    std::fs::write(
        &path,
        r#"#!/bin/sh
case "$1" in
  available) exit 0 ;;
  wrap) read k; echo "fake:$k" ;;
  unwrap) echo "$2" >> "$(dirname "$0")/unwraps"; [ -e "$(dirname "$0")/deny" ] && exit 2; read b; echo "${b#fake:}" ;;
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

fn prompt_reasons(dir: &TempDir) -> Vec<String> {
    std::fs::read_to_string(dir.path().join("unwraps"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn run_children_cannot_ride_the_session() {
    // Regression test: a command launched by `stash run` used to be able to
    // read *any* secret, unmasked and without a prompt, during a session.
    let (dir, helper) = init_with_touch_id();
    stash(&dir)
        .args(["add", "stripe/secret"])
        .write_stdin("sk_live_never_referenced")
        .assert()
        .success();
    let session = |cmd: &mut Command| {
        cmd.env_remove("STASH_PASSWORD")
            .env("STASH_TOUCHID_HELPER", &helper)
            .env("STASH_SESSION_TIMEOUT", "30");
    };

    let mut first = stash(&dir);
    session(&mut first);
    first.arg("ls").assert().success();
    assert_eq!(prompts(&dir), 1, "first unlock prompts");

    let stash_bin = assert_cmd::cargo::cargo_bin("stash");
    let mut run = stash(&dir);
    session(&mut run);
    run.env("T", "stash://k")
        .args(["run", "--"])
        .arg(&stash_bin)
        .args(["get", "stripe/secret"])
        .assert()
        .success();
    // `stash run` itself reused the session; the child had to ask for itself,
    // and the prompt said what it wanted and who wanted it.
    assert_eq!(prompts(&dir), 2, "the child needed its own unlock");
    let reason = prompt_reasons(&dir).pop().unwrap();
    assert!(reason.contains("get stripe/secret"), "{reason}");
    assert!(reason.contains("requested by stash"), "{reason}");

    let mut lock = stash(&dir);
    session(&mut lock);
    lock.arg("lock").assert().success();
}

#[test]
fn new_or_changed_env_files_and_templates_need_a_fresh_approval_even_in_a_session() {
    let (dir, helper) = init_with_touch_id();
    let session = |cmd: &mut Command| {
        cmd.env_remove("STASH_PASSWORD")
            .env("STASH_TOUCHID_HELPER", &helper)
            .env("STASH_SESSION_TIMEOUT", "30");
    };
    let stash_s = || {
        let mut cmd = stash(&dir);
        session(&mut cmd);
        cmd
    };
    let env = dir.path().join(".env");
    let run = || {
        let mut cmd = stash_s();
        cmd.args(["run", "--env-file"])
            .arg(&env)
            .args(["--", "sh", "-c", r#"printf %s "$T""#]);
        cmd
    };
    stash_s().arg("ls").assert().success();
    assert_eq!(prompts(&dir), 1);

    // A file someone else may have written: the session isn't enough.
    std::fs::write(&env, "T=stash://k\nPORT=1\n").unwrap();
    run().assert().success().stdout("v");
    assert_eq!(prompts(&dir), 2);
    let reason = prompt_reasons(&dir).pop().unwrap();
    assert!(reason.starts_with("allow "), "{reason}");
    assert!(
        reason.contains(".env (k) to give secrets to sh"),
        "{reason}"
    );

    // Approved once: the session covers it, even with plain values changed.
    std::fs::write(&env, "T=stash://k\nPORT=2\n").unwrap();
    run().assert().success().stdout("v");
    assert_eq!(prompts(&dir), 2);

    // Asking for other secrets needs a new approval; declining runs nothing.
    std::fs::write(&env, "T=stash://k\nU=stash://k\n").unwrap();
    std::fs::write(dir.path().join("deny"), "").unwrap();
    run()
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("not allowed"));
    std::fs::remove_file(dir.path().join("deny")).unwrap();
    assert_eq!(prompts(&dir), 3);

    // `stash trust` approves ahead of time, with the same check.
    stash_s().arg("trust").arg(&env).assert().success();
    assert_eq!(prompts(&dir), 4);
    run().assert().success().stdout("v");
    assert_eq!(prompts(&dir), 4);
    stash_s()
        .args(["trust", "--remove"])
        .arg(&env)
        .assert()
        .success();
    run().assert().success();
    assert_eq!(prompts(&dir), 5);

    // Templates for `stash inject` too.
    let tpl = dir.path().join("config.tpl");
    std::fs::write(&tpl, "key: {{ stash://k }}\n").unwrap();
    let inject = || {
        let mut cmd = stash_s();
        cmd.args(["inject", "-i"]).arg(&tpl);
        cmd
    };
    inject().assert().success().stdout("key: v\n");
    assert_eq!(prompts(&dir), 6);
    inject().assert().success();
    assert_eq!(prompts(&dir), 6);

    // References from your own environment (not a file) need nothing more.
    stash_s()
        .env("T", "stash://k")
        .args(["run", "--", "true"])
        .assert()
        .success();
    assert_eq!(prompts(&dir), 6);

    stash_s().arg("lock").assert().success();
}

#[test]
fn stash_trust_names_the_files_on_its_prompt_and_reports_unreadable_ones() {
    let (dir, helper) = init_with_touch_id();
    let env = dir.path().join(".env");
    std::fs::write(&env, "T=stash://k\n").unwrap();
    // No session: the unlock prompt is the approval, so it names the file.
    stash_interactive(&dir, &helper)
        .env("STASH_SESSION_TIMEOUT", "0")
        .arg("trust")
        .arg(&env)
        .assert()
        .success();
    assert_eq!(prompts(&dir), 1);
    let reason = prompt_reasons(&dir).pop().unwrap();
    assert!(
        reason.contains(".env (k) to give secrets to commands"),
        "{reason}"
    );

    std::fs::write(&env, "not a valid line\n").unwrap();
    stash(&dir)
        .arg("trust")
        .arg(&env)
        .assert()
        .failure()
        .stderr(predicate::str::contains("as a .env file: line 1"));
    stash(&dir)
        .arg("trust")
        .arg(dir.path().join("missing.env"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("could not read"));
}

#[test]
fn sessions_pause_while_an_ai_agent_runs_unless_allowed() {
    let (dir, helper) = init_with_touch_id();
    let stash_s = || {
        let mut cmd = stash(&dir);
        cmd.env_remove("STASH_PASSWORD")
            .env("STASH_TOUCHID_HELPER", &helper)
            .env("STASH_SESSION_TIMEOUT", "30")
            // Its own name, so tests running alongside don't see this agent.
            .env("STASH_AI_AGENTS", "stash-pause-test-agent");
        cmd
    };
    stash_s().arg("ls").assert().success();
    stash_s().arg("ls").assert().success();
    assert_eq!(prompts(&dir), 1, "the session covers the second command");

    // An "AI agent" starts (a script with the watched name).
    let agent = dir.path().join("stash-pause-test-agent");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&agent, "#!/bin/sh\nwhile :; do sleep 1; done\n").unwrap();
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut running = std::process::Command::new(&agent).spawn().unwrap();
    stash_s()
        .arg("agents")
        .assert()
        .success()
        .stdout(predicate::str::contains("Running: stash-pause-test-agent"));
    stash_s().arg("ls").assert().success();
    assert_eq!(prompts(&dir), 2, "the session is paused");
    let reason = prompt_reasons(&dir).pop().unwrap();
    assert!(
        reason.contains("(sessions pause while stash-pause-test-agent runs)"),
        "{reason}"
    );

    // Allowing it takes a fresh approval (here, the paused unlock itself).
    stash_s()
        .args(["agents", "--allow-sessions"])
        .assert()
        .success();
    assert_eq!(prompts(&dir), 3);
    stash_s().arg("ls").assert().success();
    assert_eq!(prompts(&dir), 3, "allowed: the session works again");

    stash_s()
        .args(["agents", "--pause-sessions"])
        .assert()
        .success();
    stash_s().arg("ls").assert().success();
    assert_eq!(prompts(&dir), 4, "paused again");

    running.kill().unwrap();
    running.wait().unwrap();
    stash_s().arg("ls").assert().success();
    assert_eq!(prompts(&dir), 4, "no agent: the session works");
    stash_s().arg("lock").assert().success();
}

#[test]
fn unlock_prompts_describe_the_request() {
    let (dir, helper) = init_with_touch_id();
    stash_interactive(&dir, &helper)
        .env("STASH_SESSION_TIMEOUT", "0")
        .env("TOKEN", "stash://k")
        .args(["run", "--", "true"])
        .assert()
        .success();
    let reason = prompt_reasons(&dir).pop().unwrap();
    assert!(
        reason.starts_with("unlock stash for “run true with k”, requested by "),
        "{reason}"
    );
}

#[test]
fn run_forwards_sigint_and_sigterm_when_not_in_the_terminal_foreground() {
    // Tests have no terminal, so Ctrl-C can't reach the child directly and
    // stash must pass SIGINT on (as for `kill -INT` or an IDE stop button).
    let dir = init_with_secrets();
    for (signal, name) in [(libc_sig::SIGINT, "INT"), (libc_sig::SIGTERM, "TERM")] {
        let script = format!(
            r#"trap 'echo got {name}; exit 9' {name}; echo ready; while :; do sleep 0.05; done"#
        );
        let mut child = std::process::Command::cargo_bin("stash")
            .unwrap()
            .env("STASH_AI_AGENTS", "stash-test-agent")
            .env("STASH_VAULT", dir.path().join("vault.db"))
            .env("STASH_AGENT_SOCK", dir.path().join("agent.sock"))
            .env("STASH_PASSWORD", PASSWORD)
            .env("TOKEN", "stash://github/token")
            .args(["run", "--", "sh", "-c", &script])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        std::io::BufRead::read_line(&mut out, &mut line).unwrap();
        assert_eq!(line, "ready\n");
        // SAFETY: sending a signal to our own child process.
        unsafe { libc_sig::kill(child.id() as i32, signal) };
        let status = child.wait().unwrap();
        let mut rest = String::new();
        std::io::Read::read_to_string(&mut out, &mut rest).unwrap();
        assert_eq!(rest, format!("got {name}\n"), "SIG{name}");
        assert_eq!(status.code(), Some(9), "SIG{name}: child's exit code");
    }
}

/// Minimal signal FFI for the test above, without a libc dev-dependency.
mod libc_sig {
    pub const SIGINT: i32 = 2;
    pub const SIGTERM: i32 = 15;
    unsafe extern "C" {
        pub fn kill(pid: i32, sig: i32) -> i32;
    }
}

#[test]
fn run_does_not_hang_on_background_grandchildren() {
    let dir = init_with_secrets();
    let started = std::time::Instant::now();
    stash(&dir)
        .env("TOKEN", "stash://github/token")
        .args(["run", "--", "sh", "-c", "echo hi; sleep 30 &"])
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout("hi\n");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn env_files_override_inherited_values_including_broken_references() {
    let dir = init_with_secrets();
    let env = dir.path().join(".env");
    std::fs::write(&env, "A=from-file\nBROKEN=fixed\n").unwrap();
    stash(&dir)
        .env("A", "stash://github/token")
        .env("BROKEN", "stash://not a valid name")
        .args(["run", "--env-file"])
        .arg(&env)
        .args(["--", "sh", "-c", r#"printf '%s %s' "$A" "$BROKEN""#])
        .assert()
        .success()
        .stdout("from-file fixed");

    // Not overridden: still a clear error.
    stash(&dir)
        .env("BROKEN", "stash://not a valid name")
        .args(["run", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("BROKEN"));
}

#[test]
fn inject_force_replaces_a_symlink_instead_of_writing_through_it() {
    let dir = init_with_secrets();
    let target = dir.path().join("elsewhere.txt");
    std::fs::write(&target, "untouched").unwrap();
    let out = dir.path().join("config.yml");
    std::os::unix::fs::symlink(&target, &out).unwrap();

    stash(&dir)
        .args(["inject", "--force", "-o"])
        .arg(&out)
        .write_stdin("t={{ stash://github/token }}")
        .assert()
        .success();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
    assert!(
        !std::fs::symlink_metadata(&out)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "t=ghp_abc123");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temp files left behind");
}

// ---- clipboard and 2FA codes ----

/// A fake clipboard backed by the file `clip`.
fn fake_clipboard(dir: &TempDir) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.path().join("clipboard");
    std::fs::write(
        &path,
        "#!/bin/sh\nf=\"$(dirname \"$0\")/clip\"\ncase \"$1\" in copy) cat > \"$f\" ;; paste) cat \"$f\" 2>/dev/null ;; esac\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn clip(dir: &TempDir) -> String {
    std::fs::read_to_string(dir.path().join("clip")).unwrap_or_default()
}

fn wait_for(mut done: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

#[test]
fn get_copy_puts_the_value_on_the_clipboard_and_clears_it() {
    let dir = init_with_secrets();
    let clipboard = fake_clipboard(&dir);
    stash(&dir)
        .env("STASH_CLIPBOARD_HELPER", &clipboard)
        .env("STASH_CLIPBOARD_TIMEOUT", "1")
        .args(["get", "--copy", "github/token"])
        .assert()
        .success()
        .stdout(""); // never printed
    assert_eq!(clip(&dir), "ghp_abc123");
    assert!(
        wait_for(|| clip(&dir).is_empty()),
        "clipboard was not cleared"
    );
}

#[test]
fn clearing_leaves_something_you_copied_since_alone() {
    let dir = init_with_secrets();
    let clipboard = fake_clipboard(&dir);
    stash(&dir)
        .env("STASH_CLIPBOARD_HELPER", &clipboard)
        .env("STASH_CLIPBOARD_TIMEOUT", "1")
        .args(["get", "--copy", "github/token"])
        .assert()
        .success();
    std::fs::write(dir.path().join("clip"), "something else").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1800));
    assert_eq!(clip(&dir), "something else");
}

#[test]
fn otp_prints_codes_from_uris_and_bare_secrets() {
    let dir = init();
    stash(&dir)
        .args(["add", "github/2fa"])
        .write_stdin("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8")
        .assert()
        .success();
    stash(&dir)
        .args(["add", "aws/2fa"])
        .write_stdin("JBSW Y3DP EHPK 3PXP")
        .assert()
        .success();
    let code = |name: &str| {
        let out = stash(&dir)
            .args(["otp", name])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        String::from_utf8(out).unwrap()
    };
    let eight = code("github/2fa");
    assert!(
        eight.len() == 8 && eight.bytes().all(|b| b.is_ascii_digit()),
        "{eight:?}"
    );
    let six = code("stash://aws/2fa");
    assert!(
        six.len() == 6 && six.bytes().all(|b| b.is_ascii_digit()),
        "{six:?}"
    );
}

#[test]
fn otp_explains_values_that_are_not_2fa_secrets() {
    let dir = init_with_secrets();
    stash(&dir)
        .args(["otp", "db/url"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("db/url isn't a 2FA secret"));
}
