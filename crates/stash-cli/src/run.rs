//! `stash run`: start a command with `stash://` references in its environment
//! replaced by secret values. The secrets exist only in that child process's
//! environment, never in your shell, your history, or a file.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, ErrorKind};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use stash_core::Vault;
use stash_core::reference::{self, ReferenceBuf};
use zeroize::Zeroizing;

use crate::mask::Masker;
use crate::{PASSWORD_ENV, envfile, trust, ui};

pub struct Options {
    pub env_files: Vec<PathBuf>,
    pub no_masking: bool,
    pub command: Vec<OsString>,
}

enum Value {
    Plain(String),
    Reference(ReferenceBuf),
    /// An inherited `stash://` value that doesn't parse. It's only an error if
    /// nothing overrides it, so one stray variable can't break every run.
    Invalid(String),
}

/// Variables the child gets on top of the inherited environment. References
/// in the inherited environment are included; `--env-file` variables override
/// inherited ones, and later files override earlier ones. Also: what each
/// file asks for, to approve.
fn collect_env(env_files: &[PathBuf]) -> Result<(BTreeMap<String, Value>, Vec<trust::Request>)> {
    let mut vars = BTreeMap::new();
    let mut requests = Vec::new();
    for (key, value) in std::env::vars_os() {
        let (Some(key), Some(value)) = (key.to_str(), value.to_str()) else {
            continue;
        };
        match reference::parse(value) {
            Ok(Some(name)) => {
                vars.insert(key.to_owned(), Value::Reference(name.to_owned()));
            }
            Ok(None) => {}
            Err(e) => {
                vars.insert(key.to_owned(), Value::Invalid(e.to_string()));
            }
        }
    }
    for path in env_files {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        let parsed = envfile::parse(&contents).with_context(|| path.display().to_string())?;
        requests.extend(
            trust::Request::new(trust::Kind::Env, path, &contents)
                .with_context(|| path.display().to_string())?,
        );
        for (key, value) in parsed {
            let entry = match reference::parse(&value)
                .with_context(|| format!("{}: {key}", path.display()))?
            {
                Some(r) => Value::Reference(r.to_owned()),
                None => Value::Plain(value),
            };
            vars.insert(key, entry);
        }
    }
    if let Some((key, why)) = vars.iter().find_map(|(k, v)| match v {
        Value::Invalid(why) => Some((k, why)),
        _ => None,
    }) {
        bail!("{key}: {why}");
    }
    Ok((vars, requests))
}

pub fn run(
    opts: Options,
    unlock: impl FnOnce(&str) -> Result<Vault>,
    approve: impl FnOnce(&mut Vault, &str) -> Result<()>,
) -> Result<ExitCode> {
    let (program, args) = opts.command.split_first().context("no command given")?;
    let (vars, requests) = collect_env(&opts.env_files)?;

    let mut resolved: Vec<(&str, Zeroizing<Vec<u8>>)> = Vec::new();
    let references: Vec<_> = vars
        .iter()
        .filter_map(|(key, value)| match value {
            Value::Reference(r) => Some((key.as_str(), r)),
            Value::Plain(_) | Value::Invalid(_) => None,
        })
        .collect();
    if !references.is_empty() {
        let described: Vec<String> = references.iter().map(|(_, r)| r.describe()).collect();
        let names: Vec<&str> = described.iter().map(String::as_str).collect();
        let mut purpose = format!(
            "run {} with {}",
            program.to_string_lossy(),
            summarize(&names)
        );
        if !requests.is_empty() {
            let files: Vec<String> = requests
                .iter()
                .map(|r| r.path.display().to_string())
                .collect();
            purpose.push_str(&format!(" from {}", files.join(", ")));
        }
        let mut vault = unlock(&purpose)?;
        let action = format!("give secrets to {}", program.to_string_lossy());
        trust::ensure(&mut vault, &requests, &action, approve)?;
        if crate::needs_sensitive(&vault, references.iter().map(|(_, r)| r.name.as_str()))? {
            crate::ensure_sensitive(&mut vault, &purpose)?;
        }
        let now = crate::unix_now();
        for (key, r) in references {
            let bytes = vault
                .resolve(&r.as_ref(), now)
                .with_context(|| format!("resolving {key}"))?;
            if bytes.contains(&0) {
                bail!(
                    "resolving {key}: the value of `{}` contains a NUL byte and can't be an environment variable",
                    r.describe()
                );
            }
            resolved.push((key, bytes));
        }
        // Drop the vault (and its keys) before the child runs.
        drop(vault);
    }

    let mut cmd = Command::new(program);
    cmd.args(args).env_remove(PASSWORD_ENV);
    for (key, value) in &vars {
        if let Value::Plain(value) = value {
            cmd.env(key, value);
        }
    }
    for (key, value) in &resolved {
        cmd.env(key, OsStr::from_bytes(value));
    }

    let masker = Some(Masker::new(resolved.iter().map(|(_, v)| v.as_slice())))
        .filter(|m| !opts.no_masking && !m.is_empty());
    if masker.is_some() {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }

    if !resolved.is_empty() {
        let n = resolved.len();
        let program_name = std::path::Path::new(program)
            .file_name()
            .unwrap_or(program)
            .to_string_lossy();
        let plural = if n == 1 { "" } else { "s" };
        ui::success(&format!(
            "unlocked · injected {n} secret{plural} into {program_name}"
        ));
    }

    prepare_signals(&mut cmd);
    let mut child = cmd.spawn().map_err(|e| match e.kind() {
        ErrorKind::NotFound => anyhow!("command not found: {}", program.to_string_lossy()),
        _ => anyhow!(e).context(format!("could not run {}", program.to_string_lossy())),
    })?;
    CHILD_PID.store(child.id() as i32, Ordering::Relaxed);

    let status = match masker {
        None => child.wait()?,
        Some(masker) => {
            let masker = Arc::new(masker);
            let (done, finished) = mpsc::channel();
            let pump = |reader: Box<dyn io::Read + Send>, to_stderr: bool| {
                let (masker, done) = (Arc::clone(&masker), done.clone());
                std::thread::spawn(move || {
                    let _ = if to_stderr {
                        masker.pump(reader, io::stderr().lock())
                    } else {
                        masker.pump(reader, io::stdout().lock())
                    };
                    let _ = done.send(());
                });
            };
            pump(
                Box::new(child.stdout.take().expect("stdout is piped")),
                false,
            );
            pump(
                Box::new(child.stderr.take().expect("stderr is piped")),
                true,
            );
            let status = child.wait()?;
            // Drain what's left. A background grandchild may hold the pipes
            // open forever, so don't wait on it past a short grace period.
            for _ in 0..2 {
                if finished.recv_timeout(OUTPUT_GRACE).is_err() {
                    break;
                }
            }
            status
        }
    };
    Ok(exit_code(status))
}

/// How long to keep relaying output after the command exits.
const OUTPUT_GRACE: Duration = Duration::from_millis(500);

/// "a, b, and 3 more" — keeps prompts readable.
pub(crate) fn summarize(names: &[&str]) -> String {
    const SHOWN: usize = 3;
    let mut list = names
        .iter()
        .take(SHOWN)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > SHOWN {
        list.push_str(&format!(", and {} more", names.len() - SHOWN));
    }
    list
}

/// Mirror the child's exit: its code, or 128 + signal number like a shell.
fn exit_code(status: ExitStatus) -> ExitCode {
    match (status.code(), status.signal()) {
        (Some(code), _) => ExitCode::from(code as u8),
        (None, Some(signal)) => ExitCode::from((128 + signal) as u8),
        (None, None) => ExitCode::FAILURE,
    }
}

/// Pid of the running child, for the signal handler. 0 until it's spawned,
/// so a signal in that window is dropped rather than misdirected.
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward(signal: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        // SAFETY: kill(2) is async-signal-safe.
        unsafe { libc::kill(pid, signal) };
    }
}

/// Is this process in the terminal's foreground process group? If so, the
/// terminal already sends Ctrl-C (SIGINT) and Ctrl-\ (SIGQUIT) to the whole
/// group, child included.
fn in_terminal_foreground() -> bool {
    // SAFETY: plain syscalls on stdin and our own process.
    unsafe {
        libc::isatty(libc::STDIN_FILENO) == 1
            && libc::tcgetpgrp(libc::STDIN_FILENO) == libc::getpgrp()
    }
}

/// Install signal handling *before* spawning, so there's no window where
/// Ctrl-C kills stash but leaves the child running with dead pipes.
///
/// - SIGTERM and SIGHUP (sent to stash alone, e.g. `kill` or a closed
///   terminal) are forwarded to the child.
/// - SIGINT and SIGQUIT are ignored when the terminal already delivers them
///   to the child, and forwarded otherwise (`kill -INT`, `timeout -s INT`,
///   an IDE's stop button).
///
/// The child gets default handling back before it starts: ignored signals
/// would otherwise stay ignored across exec.
fn prepare_signals(cmd: &mut Command) {
    let handler = forward as extern "C" fn(libc::c_int) as libc::sighandler_t;
    let interrupt = if in_terminal_foreground() {
        libc::SIG_IGN
    } else {
        handler
    };
    // SAFETY: `forward` only calls async-signal-safe code. The pre_exec hook
    // runs between fork and exec and only calls signal(2), which is
    // async-signal-safe.
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGHUP, handler);
        libc::signal(libc::SIGINT, interrupt);
        libc::signal(libc::SIGQUIT, interrupt);
        cmd.pre_exec(|| {
            for signal in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP] {
                libc::signal(signal, libc::SIG_DFL);
            }
            Ok(())
        });
    }
}
