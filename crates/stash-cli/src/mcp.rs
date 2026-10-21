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
use stash_core::reference::{self, ReferenceBuf};
use stash_core::{Kind, Vault};
use zeroize::Zeroizing;

use crate::mask::Masker;
use crate::{PASSWORD_ENV, audit, procinfo, touchid};

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
    /// Let agents use payment cards and bank accounts (off by default).
    pub allow_payments: bool,
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
        launcher: crate::procinfo::requester_chain(2),
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
    /// The sensitive key from the Touch ID unlock this request just did,
    /// usable by this request only.
    fresh_sensitive: Option<stash_core::crypto::SecretKey>,
}

struct Server {
    vault_path: PathBuf,
    audit_log: audit::Log,
    opts: Options,
    client: String,
    /// The process chain that started this server (e.g. "claude ← zsh"),
    /// from the kernel. The client's name is whatever it says it is; this
    /// isn't.
    launcher: String,
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
            "tools/call" => {
                let result = self.call_tool(&params);
                // Whatever happened, no sensitive key outlives the request.
                self.forget_sensitive();
                Ok(result)
            }
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

        let (vault, approved, fresh_sensitive) = if let Ok(password) = std::env::var(PASSWORD_ENV) {
            let password = Zeroizing::new(password);
            let mut vault = Vault::open(&self.vault_path, password.as_bytes())?;
            crate::after_password_unlock(&self.vault_path, &vault);
            // Kept only for the moment of use (see `sensitive_for`).
            vault.lock_sensitive();
            (vault, false, None)
        } else {
            let helper = self.touch_id_helper()?;
            if !touchid::is_enrolled(&self.vault_path) {
                return Err(Refusal::new(
                    "error",
                    "stash mcp needs Touch ID unlock. Ask the user to run `stash touchid enable`.",
                ));
            }
            let keys = touchid::unlock(&helper, &self.vault_path, &self.reason(purpose))
                .map_err(touch_id_refusal)?;
            (
                Vault::open_with_key(&self.vault_path, &keys.main)?,
                true,
                keys.sensitive,
            )
        };
        self.audit_log.pin(&vault);
        let unlocked = self.unlocked.insert(Unlocked {
            vault,
            last_used: Instant::now(),
            fresh_sensitive,
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

    /// Approve a request that uses a card or bank account, and unlock the
    /// sensitive key for it, in one step: the fingerprint that unlocks the
    /// key is the approval. (The server never keeps that key between
    /// requests; see `forget_sensitive`.)
    fn sensitive_for(&mut self, purpose: &str, approved: bool) -> Result<(), Refusal> {
        let reason = self.reason(purpose);
        let no_approval = self.opts.no_approval;
        let path = self.vault_path.clone();
        let helper = if no_approval {
            None
        } else {
            Some(self.touch_id_helper()?)
        };
        let unlocked = self
            .unlocked
            .as_mut()
            .ok_or_else(|| Refusal::new("error", "stash is locked"))?;
        let fresh = unlocked.fresh_sensitive.take();
        if !unlocked.vault.is_current() || unlocked.vault.has_sensitive() {
            return Ok(());
        }
        if approved && let Some(key) = fresh {
            unlocked.vault.unlock_sensitive_with_key(&key)?;
            return Ok(());
        }
        if no_approval {
            let password = Zeroizing::new(std::env::var(PASSWORD_ENV).unwrap_or_default());
            unlocked.vault.unlock_sensitive(password.as_bytes())?;
            return Ok(());
        }
        let keys = touchid::unlock(&helper.expect("set unless no_approval"), &path, &reason)
            .map_err(touch_id_refusal)?;
        let key = keys.sensitive.ok_or_else(|| {
            Refusal::new(
                "error",
                "Touch ID needs updating for this vault. Ask the user to run `stash touchid enable`.",
            )
        })?;
        unlocked.vault.unlock_sensitive_with_key(&key)?;
        Ok(())
    }

    /// After every request: the sensitive key (and any unused fresh one)
    /// is dropped.
    fn forget_sensitive(&mut self) {
        if let Some(unlocked) = self.unlocked.as_mut() {
            unlocked.vault.lock_sensitive();
            unlocked.fresh_sensitive = None;
        }
    }

    /// Do any of these items need the sensitive key?
    fn uses_sensitive(&self, names: &[&str]) -> bool {
        let Some(unlocked) = &self.unlocked else {
            return false;
        };
        crate::needs_sensitive(&unlocked.vault, names.iter().copied()).unwrap_or(false)
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
        let mut risky = Vec::new();
        if self.opts.allow_reveal {
            risky.push("--allow-reveal on");
        }
        if self.opts.allow_payments {
            risky.push("--allow-payments on");
        }
        let mut via = format!("requested via {}", self.launcher);
        for flag in risky {
            via.push_str("; ");
            via.push_str(flag);
        }
        format!("let {} {purpose} ({via})", self.client)
    }

    fn list_secrets(&mut self) -> Result<Value, Refusal> {
        let allow_payments = self.opts.allow_payments;
        let (vault, _) = self.vault("list your secret names")?;
        let summaries = vault.summaries()?;
        let names: Vec<String> = summaries
            .into_iter()
            .filter(|s| s.kind != Kind::Ssh && (allow_payments || !s.kind.is_payment()))
            .map(|s| s.name)
            .filter(|n| self.allowed(n))
            .collect();
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
                "run `{}` with {}, for up to {}s",
                request.display,
                crate::run::summarize(&described.iter().map(String::as_str).collect::<Vec<_>>()),
                request.timeout.as_secs()
            );
            // Fail on missing items before bothering the user, but produce
            // values only after approval, so a 2FA code is fresh when the
            // command starts.
            let allow_payments = self.opts.allow_payments;
            let approved = {
                let (vault, approved) = self.vault(&purpose)?;
                for (_, r) in &request.references {
                    check_exists(vault, &r.as_ref(), allow_payments)?;
                }
                approved
            };
            let sensitive = self.uses_sensitive(&names);
            if sensitive {
                self.sensitive_for(&purpose, approved)?;
            } else {
                self.approve(&purpose, approved)?;
            }
            let result = (|| {
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
                Ok(())
            })();
            self.forget_sensitive();
            result?;
        }

        let output = execute(&request, &resolved).map_err(Refusal::from)?;
        event.exit_code = output.exit_code;
        if output.timed_out {
            event.detail = Some("timed out".into());
        }
        let mut status = match (output.exit_code, output.timed_out) {
            (_, true) => format!(
                "timed out after {}s and was killed",
                request.timeout.as_secs()
            ),
            (Some(code), _) => format!("exit code {code}"),
            (None, _) => "killed by a signal".into(),
        };
        if output.stopped > 0 {
            status.push_str(&format!(
                "; stopped {} background process(es) it left running with the secrets",
                output.stopped
            ));
            event.detail = Some(match event.detail.take() {
                Some(d) => format!("{d}; stopped {} left running", output.stopped),
                None => format!("stopped {} left running", output.stopped),
            });
        }
        let text = format!(
            "{status}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.stdout, output.stderr
        );
        Ok(json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": {
                "exit_code": output.exit_code,
                "timed_out": output.timed_out,
                "stopped_background": output.stopped,
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
        let allow_payments = self.opts.allow_payments;
        let approved = {
            let (vault, approved) = self.vault(&purpose)?;
            check_exists(vault, &r.as_ref(), allow_payments)?;
            approved
        };
        if self.uses_sensitive(&[&r.name]) {
            self.sensitive_for(&purpose, approved)?;
        } else {
            self.approve(&purpose, approved)?;
        }
        let value = self
            .after_approval(&purpose)
            .and_then(|vault| Ok(vault.resolve(&r.as_ref(), crate::unix_now())?));
        self.forget_sensitive();
        let value = value?;
        let text = String::from_utf8(value.to_vec())
            .map_err(|_| Refusal::new("error", format!("{shown} isn't text")))?;
        Ok(json!({ "content": [{ "type": "text", "text": text }] }))
    }
}

/// Does this reference point at something, without producing its value?
/// Does this reference point at something an agent may use, without
/// producing its value? Cards and bank accounts are refused unless the
/// server was started with --allow-payments.
fn check_exists(
    vault: &Vault,
    r: &reference::Reference,
    allow_payments: bool,
) -> Result<(), Refusal> {
    if !vault.contains(r.name)? {
        return Err(stash_core::Error::NotFound(r.name.to_owned()).into());
    }
    let kind = vault
        .summaries()?
        .into_iter()
        .find(|s| s.name == r.name)
        .map(|s| s.kind);
    if kind == Some(Kind::Ssh) {
        return Err(Refusal::new(
            "blocked",
            format!(
                "{} is an SSH key. Its private key never goes to AI agents; commands that need it \
                 (ssh, git push, signed commits) get it through the stash SSH agent, which asks the user.",
                r.name
            ),
        ));
    }
    if !allow_payments && kind.is_some_and(Kind::is_payment) {
        return Err(Refusal::new(
            "blocked",
            format!(
                "{} is a payment card or bank account, which AI agents can't use. \
                 Ask the user to start the server with `stash mcp --allow-payments` if this is intended.",
                r.name
            ),
        ));
    }
    if let Some(field) = r.field
        && vault.item_redacted(r.name)?.field(field).is_none()
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
    crate::text::clean(s, max)
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
    /// Processes the command left running (in the background, or detached
    /// with `setsid`/`nohup`), which were then stopped.
    stopped: usize,
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

/// Marks every process a command starts (it's inherited), so the ones it
/// leaves behind can be found and stopped.
const RUN_MARKER: &str = "STASH_MCP_RUN";

fn execute(request: &RunRequest, resolved: &[(String, Zeroizing<Vec<u8>>)]) -> Result<Output> {
    let marker: String = stash_core::crypto::random_bytes::<16>()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut cmd = Command::new(&request.argv[0]);
    cmd.args(&request.argv[1..])
        .env_remove(PASSWORD_ENV)
        .envs(&request.plain)
        .env(RUN_MARKER, &marker)
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
    // Whatever it left running still holds the secrets: stop it, then
    // anything left in its process group (even if it cleared the marker).
    let stopped = stop_leftovers(&marker);
    kill_group(child.id(), libc::SIGKILL);
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
        stopped,
        stdout,
        stderr,
        truncated: out_cut || err_cut,
    })
}

/// Stop every process still carrying this run's marker: politely, then not.
/// How many there were.
fn stop_leftovers(marker: &str) -> usize {
    let left = procinfo::with_env(RUN_MARKER, marker);
    for &id in &left {
        procinfo::signal(id, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut alive = left.clone();
    while !alive.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        alive.retain(|&id| procinfo::signal(id, 0));
    }
    for id in alive {
        procinfo::signal(id, libc::SIGKILL);
    }
    left.len()
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
        assert_eq!(sanitize("run \u{202E}hs.live", 40), "run hs.live");
        assert_eq!(sanitize("abcdef", 4), "abc…");
    }

    fn server() -> Server {
        Server {
            vault_path: PathBuf::from("/nonexistent/vault.db"),
            audit_log: audit::path_for(
                &std::env::temp_dir().join(format!("stash-test-audit-{}.db", std::process::id())),
            ),
            opts: Options {
                allow: vec!["github/*".into()],
                allow_reveal: false,
                allow_payments: false,
                no_approval: false,
                idle_timeout: Duration::from_secs(60),
            },
            client: "test".into(),
            launcher: "test".into(),
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
        let _ = std::fs::remove_file(s.audit_log.file());
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
            fresh_sensitive: None,
        });
        // Calling `vault()` here would re-unlock (a second prompt);
        // `after_approval` must hand back the key that was just approved.
        assert!(s.after_approval("test").is_ok());
        assert!(s.unlocked.as_ref().unwrap().last_used > long_ago);
        let _ = std::fs::remove_file(s.audit_log.file());
    }
}
