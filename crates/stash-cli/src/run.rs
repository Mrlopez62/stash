//! `stash run`: start a command with `stash://` references in its environment
//! replaced by secret values. The secrets exist only in that child process's
//! environment, never in your shell, your history, or a file.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, ErrorKind};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use secrecy::ExposeSecret;
use stash_core::{Vault, reference};
use zeroize::Zeroizing;

use crate::mask::Masker;
use crate::{PASSWORD_ENV, envfile, ui};

pub struct Options {
    pub env_files: Vec<PathBuf>,
    pub no_masking: bool,
    pub command: Vec<OsString>,
}

enum Value {
    Plain(String),
    Reference(String),
}

/// Variables the child gets on top of the inherited environment. References
/// in the inherited environment are included; `--env-file` variables override
/// inherited ones, and later files override earlier ones.
fn collect_env(env_files: &[PathBuf]) -> Result<BTreeMap<String, Value>> {
    let mut vars = BTreeMap::new();
    for (key, value) in std::env::vars_os() {
        let (Some(key), Some(value)) = (key.to_str(), value.to_str()) else {
            continue;
        };
        if let Some(name) = reference::parse(value).with_context(|| key.to_owned())? {
            vars.insert(key.to_owned(), Value::Reference(name.to_owned()));
        }
    }
    for path in env_files {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        let parsed = envfile::parse(&contents).with_context(|| path.display().to_string())?;
        for (key, value) in parsed {
            let entry = match reference::parse(&value)
                .with_context(|| format!("{}: {key}", path.display()))?
            {
                Some(name) => Value::Reference(name.to_owned()),
                None => Value::Plain(value),
            };
            vars.insert(key, entry);
        }
    }
    Ok(vars)
}

pub fn run(opts: Options, unlock: impl FnOnce() -> Result<Vault>) -> Result<ExitCode> {
    let (program, args) = opts.command.split_first().context("no command given")?;
    let vars = collect_env(&opts.env_files)?;

    let mut resolved: Vec<(&str, Zeroizing<Vec<u8>>)> = Vec::new();
    let references: Vec<_> = vars
        .iter()
        .filter_map(|(key, value)| match value {
            Value::Reference(name) => Some((key.as_str(), name.as_str())),
            Value::Plain(_) => None,
        })
        .collect();
    if !references.is_empty() {
        let vault = unlock()?;
        for (key, name) in references {
            let secret = vault
                .get(name)
                .with_context(|| format!("resolving {key}"))?;
            let bytes = secret.expose_secret();
            if bytes.contains(&0) {
                bail!(
                    "resolving {key}: the value of `{name}` contains a NUL byte and can't be an environment variable"
                );
            }
            resolved.push((key, Zeroizing::new(bytes.to_vec())));
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

    let mut child = cmd.spawn().map_err(|e| match e.kind() {
        ErrorKind::NotFound => anyhow!("command not found: {}", program.to_string_lossy()),
        _ => anyhow!(e).context(format!("could not run {}", program.to_string_lossy())),
    })?;
    forward_signals_to(child.id());

    let status = match &masker {
        None => child.wait()?,
        Some(masker) => {
            let stdout = child.stdout.take().expect("stdout is piped");
            let stderr = child.stderr.take().expect("stderr is piped");
            std::thread::scope(|s| {
                s.spawn(move || masker.pump(stdout, io::stdout().lock()));
                s.spawn(move || masker.pump(stderr, io::stderr().lock()));
                child.wait()
            })?
        }
    };
    Ok(exit_code(status))
}

/// Mirror the child's exit: its code, or 128 + signal number like a shell.
fn exit_code(status: ExitStatus) -> ExitCode {
    match (status.code(), status.signal()) {
        (Some(code), _) => ExitCode::from(code as u8),
        (None, Some(signal)) => ExitCode::from((128 + signal) as u8),
        (None, None) => ExitCode::FAILURE,
    }
}

static CHILD_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward(signal: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        // SAFETY: kill(2) is async-signal-safe.
        unsafe { libc::kill(pid, signal) };
    }
}

/// Ctrl-C and Ctrl-\ already reach the child through the terminal, so stash
/// ignores them and lets the child shut down on its own terms. Signals sent
/// only to stash (like `kill`, or a closed terminal) are passed on.
fn forward_signals_to(pid: u32) {
    CHILD_PID.store(pid as i32, Ordering::Relaxed);
    let handler = forward as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: installing handlers; `forward` only calls async-signal-safe code.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGHUP, handler);
    }
}
