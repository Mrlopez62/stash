//! `stash mcp`: an MCP server (JSON-RPC 2.0 over stdio) that lets AI agents
//! use secrets without seeing them.
//!
//! Trust model:
//! - **Touch ID is the authority, not the agent.** Every `run_with_secrets`
//!   and `request_secret` call needs a fingerprint, and the system dialog
//!   names the exact command and secrets. The agent can't answer or fake it.
//! - **No shell sessions.** The server never reads or creates agent sessions.
//!   It holds the vault key in its own memory, forgets it after the idle
//!   timeout, and never hands it to anything.
//! - **`--allow` limits the blast radius.** Secrets outside the allowed
//!   patterns are refused before any prompt.
//! - **Everything is audited.** Each call is written to the audit log, with
//!   names only, never values.
//!
//! The protocol layer is deliberately small: `initialize`, `ping`,
//! `tools/list`, and `tools/call`, one JSON message per line.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, BufRead, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use stash_core::Vault;
use stash_core::reference::{self, ReferenceBuf};
use zeroize::Zeroizing;

use crate::mask::Masker;
use crate::{PASSWORD_ENV, audit, touchid};

/// Protocol revisions this server speaks, newest first.
const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_TIMEOUT: Duration = Duration::from_secs(900);
/// Output kept per stream; beyond this only the tail is returned.
const MAX_OUTPUT: usize = 64 * 1024;

pub struct Options {
    /// Glob patterns (`*` matches anything) of secrets agents may use.
    /// Empty means all.
    pub allow: Vec<String>,
    /// Offer `request_secret`, which returns raw values.
    pub allow_reveal: bool,
    /// Skip the per-call Touch ID approval (for headless use only).
    pub no_approval: bool,
    pub idle_timeout: Duration,
}

pub fn serve(vault_path: PathBuf, opts: Options) -> Result<()> {
    let mut server = Server {
        audit_log: audit::path_for(&vault_path),
        vault_path,
        opts,
        client: "unknown-client".into(),
        unlocked: None,
    };
    let stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    for line in stdin.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(response) = server.handle_line(&line) {
            serde_json::to_writer(&mut stdout, &response)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

struct Unlocked {
    vault: Vault,
    last_used: Instant,
}

struct Server {
    vault_path: PathBuf,
    audit_log: PathBuf,
    opts: Options,
    client: String,
    unlocked: Option<Unlocked>,
}

/// A tool failure the agent should see (as `isError: true`), plus what to
/// record in the audit log.
struct Refusal {
    outcome: &'static str,
    message: String,
}

impl Refusal {
    fn new(outcome: &'static str, message: impl Into<String>) -> Self {
        Self {
            outcome,
            message: message.into(),
        }
    }
}

impl From<anyhow::Error> for Refusal {
    fn from(e: anyhow::Error) -> Self {
        Refusal::new("error", format!("{e:#}"))
    }
}

impl From<stash_core::Error> for Refusal {
    fn from(e: stash_core::Error) -> Self {
        Refusal::new("error", e.to_string())
    }
}

impl Server {
    fn handle_line(&mut self, line: &str) -> Option<Value> {
        let message: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return Some(error_response(
                    Value::Null,
                    -32700,
                    &format!("parse error: {e}"),
                ));
            }
        };
        let id = message.get("id").cloned();
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            // A response to something we never sent, or malformed: ignore
            // responses, reject the rest.
            return id
                .filter(|_| message.get("result").is_none() && message.get("error").is_none())
                .map(|id| error_response(id, -32600, "invalid request"));
        };
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        // Notifications (no id) never get a response.
        let id = id?;
        let result = match method {
            "initialize" => Ok(self.initialize(&params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": self.tool_definitions() })),
            "tools/call" => Ok(self.call_tool(&params)),
            _ => Err((-32601, format!("method not found: {method}"))),
        };
        Some(match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, msg)) => error_response(id, code, &msg),
        })
    }

    fn initialize(&mut self, params: &Value) -> Value {
        if let Some(name) = params.pointer("/clientInfo/name").and_then(Value::as_str) {
            self.client = sanitize(name, 40);
        }
        let requested = params.get("protocolVersion").and_then(Value::as_str);
        let version = requested
            .filter(|v| PROTOCOL_VERSIONS.contains(v))
            .unwrap_or(PROTOCOL_VERSIONS[0]);
        json!({
            "protocolVersion": version,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": { "name": "stash", "version": env!("CARGO_PKG_VERSION") },
            "instructions": "stash keeps the user's API keys and tokens. To use one, call \
                run_with_secrets with env values like \"stash://github/token\": the command \
                gets the real value, and its output comes back with secrets masked. You never \
                see secret values. Each call asks the user to approve it with Touch ID, so \
                batch work into one call where you can and explain why you need it.",
        })
    }

    fn tool_definitions(&self) -> Vec<Value> {
        let mut tools = vec![
            json!({
                "name": "list_secrets",
                "title": "List secret names",
                "description": "List the names of secrets you may use (never their values). \
                    Reference one as stash://<name> in run_with_secrets.",
                "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
                "annotations": { "readOnlyHint": true, "openWorldHint": false },
            }),
            json!({
                "name": "run_with_secrets",
                "title": "Run a command with secrets",
                "description": "Run a command with secrets in its environment. Set env values to \
                    \"stash://<name>\" to inject an item's main value (a login's password), or \
                    \"stash://<name>#<field>\" for one field, e.g. #username or #otp for the current \
                    2FA code; other values are passed as-is. The user \
                    approves each call with Touch ID. Returns the exit code and stdout/stderr, with \
                    any injected secret value replaced by <concealed by stash>. No shell is used: \
                    pass [\"sh\", \"-c\", \"...\"] if you need one.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "array", "items": { "type": "string" }, "minItems": 1,
                            "description": "Program and arguments, e.g. [\"npm\", \"test\"]",
                        },
                        "env": {
                            "type": "object", "additionalProperties": { "type": "string" },
                            "description": "Environment variables, e.g. {\"GITHUB_TOKEN\": \"stash://github/token\"}",
                        },
                        "cwd": { "type": "string", "description": "Working directory (default: the server's)" },
                        "timeout_seconds": {
                            "type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT.as_secs(),
                            "description": "Kill the command after this long (default 120)",
                        },
                    },
                    "required": ["command"],
                    "additionalProperties": false,
                },
                "annotations": { "destructiveHint": true, "openWorldHint": true },
            }),
        ];
        if self.opts.allow_reveal {
            tools.push(json!({
                "name": "request_secret",
                "title": "Reveal a secret's value",
                "description": "Return a secret's raw value. Prefer run_with_secrets, which never \
                    exposes values. The user must approve each reveal with Touch ID.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "name": { "type": "string", "description": "Secret name, e.g. github/token" } },
                    "required": ["name"],
                    "additionalProperties": false,
                },
                "annotations": { "readOnlyHint": true, "openWorldHint": false },
            }));
        }
        tools
    }

    fn call_tool(&mut self, params: &Value) -> Value {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        let mut event = audit::Event {
            time: audit::now_rfc3339(),
            client: self.client.clone(),
            tool: sanitize(name, 40),
            secrets: Vec::new(),
            command: None,
            outcome: "approved".into(),
            exit_code: None,
            detail: None,
        };
        let outcome = match name {
            "list_secrets" => self.list_secrets(),
            "run_with_secrets" => self.run_with_secrets(&args, &mut event),
            "request_secret" if self.opts.allow_reveal => self.request_secret(&args, &mut event),
            "request_secret" => Err(Refusal::new(
                "blocked",
                "request_secret is turned off. Use run_with_secrets, or ask the user to start \
                 the server with `stash mcp --allow-reveal`.",
            )),
            _ => Err(Refusal::new("error", format!("unknown tool: {name}"))),
        };
        let result = match outcome {
            Ok(result) => result,
            Err(refusal) => {
                event.outcome = refusal.outcome.into();
                event.detail = Some(refusal.message.clone());
                json!({ "content": [{ "type": "text", "text": refusal.message }], "isError": true })
            }
        };
        if let Err(e) = audit::record(&self.audit_log, &event) {
            eprintln!("stash mcp: {e:#}");
        }
        result
    }

    fn allowed(&self, name: &str) -> bool {
        self.opts.allow.is_empty() || self.opts.allow.iter().any(|p| glob(p, name))
    }

    fn check_allowed(&self, names: &[&str]) -> Result<(), Refusal> {
        let blocked: Vec<&str> = names.iter().copied().filter(|n| !self.allowed(n)).collect();
        if blocked.is_empty() {
            return Ok(());
        }
        Err(Refusal::new(
            "blocked",
            format!(
                "not allowed for AI agents: {} (allowed: {})",
                blocked.join(", "),
                self.opts.allow.join(", ")
            ),
        ))
    }

    /// The unlocked vault, unlocking with Touch ID if needed. Returns whether
    /// that unlock just happened: its prompt described this request, so it
    /// counts as the user's approval.
    fn vault(&mut self, purpose: &str) -> Result<(&Vault, bool), Refusal> {
        let idle = self.opts.idle_timeout;
        if self
            .unlocked
            .as_ref()
            .is_some_and(|u| u.last_used.elapsed() < idle)
        {
            let unlocked = self.unlocked.as_mut().expect("checked above");
            unlocked.last_used = Instant::now();
            return Ok((&unlocked.vault, false));
        }
        self.unlocked = None;

        let (vault, approved) = if let Ok(password) = std::env::var(PASSWORD_ENV) {
            let password = Zeroizing::new(password);
            (Vault::open(&self.vault_path, password.as_bytes())?, false)
        } else {
            let helper = self.touch_id_helper()?;
            if !touchid::is_enrolled(&self.vault_path) {
                return Err(Refusal::new(
                    "error",
                    "stash mcp needs Touch ID unlock. Ask the user to run `stash touchid enable`.",
                ));
            }
            let key = touchid::unlock(&helper, &self.vault_path, &self.reason(purpose))
                .map_err(touch_id_refusal)?;
            (Vault::open_with_key(&self.vault_path, &key)?, true)
        };
        let unlocked = self.unlocked.insert(Unlocked {
            vault,
            last_used: Instant::now(),
        });
        Ok((&unlocked.vault, approved))
    }

    /// The vault right after an approval. Uses the key that was just checked
    /// even if the idle timeout passed while the dialog was open, so a slow
    /// approval never causes a second prompt.
    fn after_approval(&mut self, purpose: &str) -> Result<&Vault, Refusal> {
        if self.unlocked.is_none() {
            return Ok(self.vault(purpose)?.0);
        }
        let unlocked = self.unlocked.as_mut().expect("checked above");
        unlocked.last_used = Instant::now();
        Ok(&unlocked.vault)
    }

    /// Ask the user to approve `purpose` with Touch ID, unless the unlock
    /// that just happened already asked.
    fn approve(&self, purpose: &str, already_approved: bool) -> Result<(), Refusal> {
        if already_approved || self.opts.no_approval {
            return Ok(());
        }
        let helper = self.touch_id_helper()?;
        touchid::confirm(&helper, &self.reason(purpose)).map_err(touch_id_refusal)
    }

    fn touch_id_helper(&self) -> Result<PathBuf, Refusal> {
        touchid::helper().ok_or_else(|| {
            Refusal::new(
                "error",
                "the stash-touchid helper was not found, so requests can't be approved. \
                 Ask the user to install it (see the stash README).",
            )
        })
    }

    /// Finishes the Touch ID dialog's sentence "stash-touchid is trying to …".
    fn reason(&self, purpose: &str) -> String {
        format!("let {} {purpose}", self.client)
    }

    fn list_secrets(&mut self) -> Result<Value, Refusal> {
        let (vault, _) = self.vault("list your secret names")?;
        let names = vault.names()?;
        let names: Vec<String> = names.into_iter().filter(|n| self.allowed(n)).collect();
        let text = if names.is_empty() {
            "No secrets available.".to_owned()
        } else {
            names.join("\n")
        };
        Ok(json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": { "names": names },
        }))
    }

    fn run_with_secrets(
        &mut self,
        args: &Value,
        event: &mut audit::Event,
    ) -> Result<Value, Refusal> {
        let request =
            RunRequest::parse(args).map_err(|e| Refusal::new("error", format!("{e:#}")))?;
        let names: Vec<&str> = request
            .references
            .iter()
            .map(|(_, r)| r.name.as_str())
            .collect();
        let described: Vec<String> = request
            .references
            .iter()
            .map(|(_, r)| r.describe())
            .collect();
        event.secrets = described.clone();
        event.command = Some(request.display.clone());
        self.check_allowed(&names)?;

        let mut resolved: Vec<(String, Zeroizing<Vec<u8>>)> = Vec::new();
        if !names.is_empty() {
            let purpose = format!(
                "run `{}` with {}",
                request.display,
                crate::run::summarize(&described.iter().map(String::as_str).collect::<Vec<_>>())
            );
            // Fail on missing items before bothering the user, but produce
            // values only after approval, so a 2FA code is fresh when the
            // command starts.
            let approved = {
                let (vault, approved) = self.vault(&purpose)?;
                for (_, r) in &request.references {
                    check_exists(vault, &r.as_ref())?;
                }
                approved
            };
            self.approve(&purpose, approved)?;
            let vault = self.after_approval(&purpose)?;
            let now = crate::unix_now();
            for (key, r) in &request.references {
                let value = vault.resolve(&r.as_ref(), now)?;
                if value.contains(&0) {
                    return Err(Refusal::new(
                        "error",
                        format!("{} contains a NUL byte", r.describe()),
                    ));
                }
                resolved.push((key.clone(), value));
            }
        }

        let output = execute(&request, &resolved).map_err(Refusal::from)?;
        event.exit_code = output.exit_code;
        if output.timed_out {
            event.detail = Some("timed out".into());
        }
        let status = match (output.exit_code, output.timed_out) {
            (_, true) => format!(
                "timed out after {}s and was killed",
                request.timeout.as_secs()
            ),
            (Some(code), _) => format!("exit code {code}"),
            (None, _) => "killed by a signal".into(),
        };
        let text = format!(
            "{status}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.stdout, output.stderr
        );
        Ok(json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": {
                "exit_code": output.exit_code,
                "timed_out": output.timed_out,
                "stdout": output.stdout,
                "stderr": output.stderr,
                "truncated": output.truncated,
            },
        }))
    }

    fn request_secret(&mut self, args: &Value, event: &mut audit::Event) -> Result<Value, Refusal> {
        let name = args
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| Refusal::new("error", "missing `name`"))?;
        let r = reference::parse_arg(name)
            .map_err(|e| Refusal::new("error", e.to_string()))?
            .to_owned();
        let shown = r.describe();
        event.secrets = vec![shown.clone()];
        self.check_allowed(&[&r.name])?;

        let purpose = format!("see the value of {shown}");
        let approved = {
            let (vault, approved) = self.vault(&purpose)?;
            check_exists(vault, &r.as_ref())?;
            approved
        };
        self.approve(&purpose, approved)?;
        let vault = self.after_approval(&purpose)?;
        let value = vault.resolve(&r.as_ref(), crate::unix_now())?;
        let text = String::from_utf8(value.to_vec())
            .map_err(|_| Refusal::new("error", format!("{shown} isn't text")))?;
        Ok(json!({ "content": [{ "type": "text", "text": text }] }))
    }
}

/// Does this reference point at something, without producing its value?
fn check_exists(vault: &Vault, r: &reference::Reference) -> Result<(), Refusal> {
    if !vault.contains(r.name)? {
        return Err(stash_core::Error::NotFound(r.name.to_owned()).into());
    }
    if let Some(field) = r.field
        && vault.item(r.name)?.field(field).is_none()
    {
        return Err(stash_core::Error::NoSuchField(r.name.to_owned(), field.to_owned()).into());
    }
    Ok(())
}

fn touch_id_refusal(e: touchid::UnlockError) -> Refusal {
    match e {
        touchid::UnlockError::Cancelled => Refusal::new(
            "denied",
            "The user declined this request in the Touch ID prompt.",
        ),
        touchid::UnlockError::Unavailable(why) => Refusal::new(
            "error",
            format!("Touch ID is unavailable ({why}), so the request can't be approved."),
        ),
        touchid::UnlockError::Failed(why) => {
            Refusal::new("error", format!("Touch ID failed: {why}"))
        }
    }
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Keep agent-supplied text readable and short in prompts and logs.
fn sanitize(s: &str, max: usize) -> String {
    let clean: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if clean.chars().count() > max {
        let mut cut: String = clean.chars().take(max - 1).collect();
        cut.push('…');
        cut
    } else {
        clean
    }
}

/// `*` matches any run of characters, including `/`.
fn glob(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((prefix, rest)) => {
            let Some(tail) = name.strip_prefix(prefix) else {
                return false;
            };
            (0..=tail.len())
                .filter(|&i| tail.is_char_boundary(i))
                .any(|i| glob(rest, &tail[i..]))
        }
    }
}

struct RunRequest {
    argv: Vec<String>,
    plain: BTreeMap<String, String>,
    references: Vec<(String, ReferenceBuf)>,
    cwd: Option<PathBuf>,
    timeout: Duration,
    /// For prompts and the audit log.
    display: String,
}

impl RunRequest {
    fn parse(args: &Value) -> Result<Self> {
        let argv: Vec<String> = args
            .get("command")
            .and_then(Value::as_array)
            .context("`command` must be an array of strings")?
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<_>>()
            .context("`command` must be an array of strings")?;
        if argv.is_empty() || argv[0].is_empty() {
            bail!("`command` must not be empty");
        }
        let mut plain = BTreeMap::new();
        let mut references = Vec::new();
        if let Some(env) = args.get("env") {
            let env = env.as_object().context("`env` must be an object")?;
            for (key, value) in env {
                let value = value
                    .as_str()
                    .with_context(|| format!("env `{key}` must be a string"))?;
                if key.is_empty() || key.contains('=') || key.contains('\0') {
                    bail!("invalid environment variable name `{key}`");
                }
                match reference::parse(value).with_context(|| format!("env `{key}`"))? {
                    Some(r) => references.push((key.clone(), r.to_owned())),
                    None => {
                        plain.insert(key.clone(), value.to_owned());
                    }
                }
            }
        }
        let timeout = match args.get("timeout_seconds") {
            None => DEFAULT_TIMEOUT,
            Some(v) => {
                let secs = v
                    .as_u64()
                    .filter(|&s| s > 0)
                    .context("`timeout_seconds` must be a positive integer")?;
                Duration::from_secs(secs).min(MAX_TIMEOUT)
            }
        };
        let cwd = args
            .get("cwd")
            .map(|v| {
                v.as_str()
                    .map(PathBuf::from)
                    .context("`cwd` must be a string")
            })
            .transpose()?;
        let display = sanitize(
            &argv
                .iter()
                .map(|a| {
                    if a.is_empty() || a.contains(char::is_whitespace) {
                        format!("'{a}'")
                    } else {
                        a.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
            80,
        );
        Ok(Self {
            argv,
            plain,
            references,
            cwd,
            timeout,
            display,
        })
    }
}

struct Output {
    exit_code: Option<i32>,
    timed_out: bool,
    stdout: String,
    stderr: String,
    truncated: bool,
}

/// Keeps the last `MAX_OUTPUT` bytes written to it.
#[derive(Default)]
struct Tail {
    buf: Vec<u8>,
    truncated: bool,
}

impl Write for Tail {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.buf.len() > MAX_OUTPUT {
            let excess = self.buf.len() - MAX_OUTPUT;
            self.buf.drain(..excess);
            self.truncated = true;
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Writes into a shared `Tail`, so the pump thread can be abandoned.
struct SharedTail(Arc<Mutex<Tail>>);

impl Write for SharedTail {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("tail lock").write(data)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn execute(request: &RunRequest, resolved: &[(String, Zeroizing<Vec<u8>>)]) -> Result<Output> {
    let mut cmd = Command::new(&request.argv[0]);
    cmd.args(&request.argv[1..])
        .env_remove(PASSWORD_ENV)
        .envs(&request.plain)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Its own process group, so a timeout can stop everything it started.
        .process_group(0);
    for (key, value) in resolved {
        cmd.env(key, OsStr::from_bytes(value));
    }
    if let Some(cwd) = &request.cwd {
        cmd.current_dir(cwd);
    }
    let mut child = cmd.spawn().map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => anyhow!("command not found: {}", request.argv[0]),
        _ => anyhow!(e).context(format!("could not run {}", request.argv[0])),
    })?;

    let masker = Arc::new(Masker::new(resolved.iter().map(|(_, v)| v.as_slice())));
    let (done, finished) = mpsc::channel();
    let pump = |reader: Box<dyn io::Read + Send>| {
        let tail = Arc::new(Mutex::new(Tail::default()));
        let (masker, done, sink) = (Arc::clone(&masker), done.clone(), Arc::clone(&tail));
        std::thread::spawn(move || {
            let _ = masker.pump(reader, SharedTail(sink));
            let _ = done.send(());
        });
        tail
    };
    let stdout = pump(Box::new(child.stdout.take().expect("piped")));
    let stderr = pump(Box::new(child.stderr.take().expect("piped")));

    let deadline = Instant::now() + request.timeout;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            kill_group(child.id(), libc::SIGTERM);
            let grace = Instant::now() + Duration::from_secs(3);
            while Instant::now() < grace && child.try_wait()?.is_none() {
                std::thread::sleep(Duration::from_millis(50));
            }
            kill_group(child.id(), libc::SIGKILL);
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    for _ in 0..2 {
        if finished.recv_timeout(Duration::from_millis(500)).is_err() {
            break;
        }
    }

    let take = |tail: &Arc<Mutex<Tail>>| {
        let tail = tail.lock().expect("tail lock");
        (
            String::from_utf8_lossy(&tail.buf).into_owned(),
            tail.truncated,
        )
    };
    let (stdout, out_cut) = take(&stdout);
    let (stderr, err_cut) = take(&stderr);
    Ok(Output {
        exit_code: status.code(),
        timed_out,
        stdout,
        stderr,
        truncated: out_cut || err_cut,
    })
}

fn kill_group(pid: u32, signal: libc::c_int) {
    // SAFETY: signalling the process group we created for this child.
    unsafe { libc::kill(-(pid as i32), signal) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_match_names() {
        assert!(glob("github/*", "github/token"));
        assert!(glob("*", "anything/at/all"));
        assert!(glob("*/token", "github/token"));
        assert!(glob("exact", "exact"));
        assert!(!glob("github/*", "gitlab/token"));
        assert!(!glob("exact", "exactly"));
        assert!(glob("a*b*c", "a-x-b-y-c"));
    }

    #[test]
    fn parses_run_requests() {
        let r = RunRequest::parse(&json!({
            "command": ["npm", "run", "a b"],
            "env": { "TOKEN": "stash://github/token", "PORT": "3000" },
            "timeout_seconds": 5000,
        }))
        .unwrap();
        assert_eq!(r.references.len(), 1);
        assert_eq!(r.references[0].0, "TOKEN");
        assert_eq!(r.references[0].1.describe(), "github/token");
        assert_eq!(r.plain.get("PORT").unwrap(), "3000");
        assert_eq!(r.timeout, MAX_TIMEOUT);
        assert_eq!(r.display, "npm run 'a b'");
    }

    #[test]
    fn rejects_bad_run_requests() {
        for bad in [
            json!({}),
            json!({ "command": [] }),
            json!({ "command": "npm test" }),
            json!({ "command": ["x"], "env": { "A": 1 } }),
            json!({ "command": ["x"], "env": { "A=B": "v" } }),
            json!({ "command": ["x"], "env": { "A": "stash://bad name" } }),
            json!({ "command": ["x"], "timeout_seconds": 0 }),
        ] {
            assert!(RunRequest::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn tail_keeps_the_end_of_long_output() {
        let mut tail = Tail::default();
        tail.write_all(&vec![b'a'; MAX_OUTPUT]).unwrap();
        tail.write_all(b"END").unwrap();
        assert!(tail.truncated);
        assert_eq!(tail.buf.len(), MAX_OUTPUT);
        assert!(tail.buf.ends_with(b"END"));
    }

    #[test]
    fn sanitizes_agent_text() {
        assert_eq!(sanitize("a\nb\x1b[31m", 40), "a b [31m");
        assert_eq!(sanitize("abcdef", 4), "abc…");
    }

    fn server() -> Server {
        Server {
            vault_path: PathBuf::from("/nonexistent/vault.db"),
            audit_log: std::env::temp_dir()
                .join(format!("stash-test-audit-{}", std::process::id())),
            opts: Options {
                allow: vec!["github/*".into()],
                allow_reveal: false,
                no_approval: false,
                idle_timeout: Duration::from_secs(60),
            },
            client: "test".into(),
            unlocked: None,
        }
    }

    #[test]
    fn speaks_the_protocol_basics() {
        let mut s = server();
        let init = s
            .handle_line(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"claude-code"}}}"#)
            .unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(s.client, "claude-code");
        assert!(
            s.handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .is_none()
        );
        let tools = s
            .handle_line(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
            .unwrap();
        let names: Vec<&str> = tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["list_secrets", "run_with_secrets"]);
        let unknown = s
            .handle_line(r#"{"jsonrpc":"2.0","id":3,"method":"nope"}"#)
            .unwrap();
        assert_eq!(unknown["error"]["code"], -32601);
        let garbage = s.handle_line("{not json").unwrap();
        assert_eq!(garbage["error"]["code"], -32700);
        let future = s
            .handle_line(r#"{"jsonrpc":"2.0","id":4,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}"#)
            .unwrap();
        assert_eq!(future["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
    }

    #[test]
    fn blocks_secrets_outside_the_allowlist_before_unlocking() {
        let mut s = server();
        let call = s
            .handle_line(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_with_secrets","arguments":{"command":["true"],"env":{"K":"stash://stripe/secret"}}}}"#)
            .unwrap();
        assert_eq!(call["result"]["isError"], true);
        let text = call["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("not allowed for AI agents: stripe/secret"),
            "{text}"
        );
        let _ = std::fs::remove_file(&s.audit_log);
    }

    #[test]
    fn a_slow_approval_reuses_the_approved_key_instead_of_prompting_again() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vault.db");
        let fast = stash_core::KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let vault = Vault::create(&path, b"pw", fast).unwrap();
        let mut s = server();
        s.vault_path = path;
        s.opts.idle_timeout = Duration::from_secs(1);
        // As if the Touch ID dialog stayed open well past the idle timeout.
        let long_ago = Instant::now()
            .checked_sub(Duration::from_secs(3600))
            .unwrap();
        s.unlocked = Some(Unlocked {
            vault,
            last_used: long_ago,
        });
        // Calling `vault()` here would re-unlock (a second prompt);
        // `after_approval` must hand back the key that was just approved.
        assert!(s.after_approval("test").is_ok());
        assert!(s.unlocked.as_ref().unwrap().last_used > long_ago);
        let _ = std::fs::remove_file(&s.audit_log);
    }
}
