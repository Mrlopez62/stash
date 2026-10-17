mod agent;
mod audit;
mod clipboard;
mod envfile;
mod inject;
mod items;
mod mask;
mod mcp;
mod procinfo;
mod run;
mod touchid;
mod ui;

use std::ffi::OsString;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use stash_core::reference;
use stash_core::{KdfParams, Vault};
use zeroize::Zeroizing;

/// A free, developer-first secrets manager.
#[derive(Parser)]
#[command(name = "stash", version, about)]
struct Cli {
    /// Path to the vault file [default: ~/.stash/vault.db]
    #[arg(long, global = true, env = "STASH_VAULT")]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault protected by a master password
    Init,
    /// Store a secret, login, or note (secret values are read from stdin or
    /// a prompt without echo, never from flags)
    #[command(
        after_help = "Examples:\n  stash add openai/api-key                     # a single secret\n  stash add github --login --username octocat --url https://github.com --generate\n  stash add github --login --otp               # asks for the password and 2FA secret\n  stash add notes/wifi --note"
    )]
    Add {
        /// Item name, e.g. `github/token`
        name: String,
        /// Overwrite the item if it already exists
        #[arg(long, short)]
        force: bool,
        /// Create a login (username, password, website, 2FA)
        #[arg(long, conflicts_with = "note")]
        login: bool,
        /// Create a secure note
        #[arg(long)]
        note: bool,
        #[command(flatten)]
        fields: items::LoginArgs,
    },
    /// Change an item's fields
    #[command(
        after_help = "Examples:\n  stash edit github --generate               # new random password\n  stash edit github --otp                    # add or replace 2FA\n  stash edit github --set recovery-email=me@example.com --unset website"
    )]
    Edit {
        /// Item name
        name: String,
        #[command(flatten)]
        args: items::EditArgs,
    },
    /// Show an item's fields (hidden values stay hidden unless --reveal)
    Show {
        /// Item name
        name: String,
        /// Show passwords, 2FA codes, and notes
        #[arg(long)]
        reveal: bool,
    },
    /// Generate a random password
    Generate {
        #[command(flatten)]
        rules: items::GenerateArgs,
        /// Copy it to the clipboard instead of printing it
        #[arg(long, short)]
        copy: bool,
    },
    /// Print a value: an item's main value (a login's password), or one field
    Get {
        /// Item name, `name#field` (e.g. `github#username`, `github#otp`), or a
        /// `stash://` reference
        name: String,
        /// Copy to the clipboard instead of printing; cleared after 30 seconds
        /// (STASH_CLIPBOARD_TIMEOUT) if it hasn't changed
        #[arg(long, short)]
        copy: bool,
    },
    /// Print the current 2FA code for a TOTP secret
    ///
    /// The secret's value is an `otpauth://totp/...` URI (what a 2FA QR code
    /// contains) or a bare base32 secret.
    #[command(
        after_help = "Example:\n  stash add github/2fa          # paste the otpauth:// URI or base32 secret\n  stash otp github/2fa --copy"
    )]
    Otp {
        /// Secret name or reference
        name: String,
        /// Copy the code to the clipboard instead of printing it
        #[arg(long, short)]
        copy: bool,
    },
    /// List item names (never values)
    #[command(alias = "list")]
    Ls {
        /// Also show each item's kind, username, website, and 2FA
        #[arg(long, short)]
        long: bool,
    },
    /// Delete a secret
    #[command(alias = "remove")]
    Rm {
        /// Secret name, e.g. `github/token`
        name: String,
    },
    /// Run a command with `stash://` references in its environment replaced by secrets
    ///
    /// Any environment variable (inherited or from --env-file) whose whole
    /// value is `stash://<name>` is replaced with that secret, only for the
    /// command being run. Secret values in its output are hidden unless
    /// --no-masking is given. The command's exit code is passed through.
    #[command(
        after_help = "Example:\n  echo 'GITHUB_TOKEN=stash://github/token' > .env\n  stash run --env-file .env -- npm start"
    )]
    Run {
        /// Load variables from a .env file (repeatable; later files win)
        #[arg(long = "env-file", value_name = "FILE")]
        env_files: Vec<PathBuf>,
        /// Show secret values in the command's output instead of hiding them
        #[arg(long)]
        no_masking: bool,
        /// The command to run and its arguments
        #[arg(
            required = true,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<OsString>,
    },
    /// Fill `{{ stash://<name> }}` placeholders in a template with secrets
    #[command(after_help = "Example:\n  stash inject -i config.tpl.yml -o config.yml")]
    Inject {
        /// Template file [default: stdin]
        #[arg(long, short)]
        input: Option<PathBuf>,
        /// Output file, created readable only by you [default: stdout]
        #[arg(long, short)]
        output: Option<PathBuf>,
        /// Overwrite the output file if it exists
        #[arg(long, short)]
        force: bool,
    },
    /// Serve MCP over stdio, so AI agents can use secrets without seeing them
    ///
    /// Agents can list secret names and run commands with secrets injected.
    /// Each run (and each reveal, if allowed) needs your Touch ID approval,
    /// and the prompt names the exact command and secrets. Every request is
    /// written to the audit log (`stash audit`).
    #[command(
        after_help = "Add to Claude Code:\n  claude mcp add stash -- stash mcp --allow 'github/*'"
    )]
    Mcp {
        /// Only let agents use secrets matching this pattern (`*` matches anything;
        /// repeatable) [default: all secrets]
        #[arg(long, value_name = "PATTERN")]
        allow: Vec<String>,
        /// Offer the request_secret tool, which returns raw values to the agent
        #[arg(long)]
        allow_reveal: bool,
        /// Don't ask for Touch ID per request (headless use with STASH_PASSWORD only)
        #[arg(long)]
        no_approval: bool,
    },
    /// Show recent AI-agent requests from the audit log
    Audit {
        /// How many entries to show
        #[arg(long, short = 'n', default_value_t = 20)]
        limit: usize,
    },
    /// End the unlocked session, so the next command asks again
    Lock,
    /// Unlock with your fingerprint instead of the master password (macOS)
    #[command(name = "touchid")]
    TouchId {
        #[command(subcommand)]
        action: TouchIdAction,
    },
    /// Clear the clipboard later if unchanged (started automatically)
    #[command(hide = true)]
    ClipboardClear {
        #[arg(long)]
        after: u64,
    },
    /// Run the session agent (started automatically; not for direct use)
    #[command(hide = true)]
    Agent {
        #[arg(long)]
        socket: PathBuf,
    },
}

#[derive(Subcommand)]
enum TouchIdAction {
    /// Turn on Touch ID unlock (asks for the master password once)
    Enable,
    /// Turn off Touch ID unlock
    Disable,
    /// Show whether Touch ID unlock is available and turned on
    Status,
}

/// Read from the environment instead of prompting. Meant for scripts and CI:
/// anything that can read your environment can read this password.
pub(crate) const PASSWORD_ENV: &str = "STASH_PASSWORD";
const MIN_PASSWORD_LEN: usize = 8;
/// Seconds an unlocked session lasts without use. `0` turns sessions off.
const SESSION_TIMEOUT_ENV: &str = "STASH_SESSION_TIMEOUT";
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(10 * 60);

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("stash: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match &cli.command {
        Command::Agent { socket } => {
            agent::serve(socket)?;
            return Ok(ExitCode::SUCCESS);
        }
        Command::ClipboardClear { after } => {
            clipboard::clear_if_unchanged(Duration::from_secs(*after))?;
            return Ok(ExitCode::SUCCESS);
        }
        _ => {}
    }
    let path = match cli.vault {
        Some(path) => path,
        None => default_vault_path()?,
    };

    match cli.command {
        Command::Init => {
            let password = new_password()?;
            Vault::create(&path, password.as_bytes(), KdfParams::default())?;
            eprintln!("Created vault at {}", path.display());
            if cfg!(target_os = "macos") {
                eprintln!("Tip: run `stash touchid enable` to unlock with your fingerprint.");
            }
        }
        Command::Add {
            name,
            force,
            login,
            note,
            fields,
        } => {
            stash_core::validate_name(&name)?;
            let mut vault = unlock(&path, &format!("add {name}"))?;
            if login {
                items::add_login(&mut vault, &name, &fields, force)?;
            } else if note {
                items::add_note(&mut vault, &name, force)?;
            } else {
                if fields.username.is_some()
                    || fields.url.is_some()
                    || fields.otp
                    || fields.generate
                {
                    bail!("--username, --url, --otp, and --generate need --login");
                }
                let value = read_value(&name)?;
                vault.add(&name, &value, force)?;
                eprintln!("Saved {name}");
            }
        }
        Command::Edit { name, args } => {
            stash_core::validate_name(&name)?;
            let mut vault = unlock(&path, &format!("edit {name}"))?;
            items::edit(&mut vault, &name, &args)?;
        }
        Command::Show { name, reveal } => {
            let r = reference::parse_arg(&name)?;
            let vault = unlock(&path, &format!("show {}", r.name))?;
            items::show(&vault, r.name, reveal)?;
        }
        Command::Generate { rules, copy } => {
            let password = stash_core::generate::password(rules.rules())?;
            if copy {
                copy_to_clipboard(password.as_bytes(), "a new password")?;
            } else {
                print_secret(password.as_bytes())?;
            }
        }
        Command::Get { name, copy } => {
            let r = reference::parse_arg(&name)?;
            let shown = r.describe();
            let vault = unlock(&path, &format!("get {shown}"))?;
            let value = vault.resolve(&r, unix_now())?;
            if copy {
                copy_to_clipboard(&value, &shown)?;
            } else {
                print_secret(&value)?;
            }
        }
        Command::Otp { name, copy } => {
            let name = reference::parse_arg(&name)?.name;
            let vault = unlock(&path, &format!("get a 2FA code for {name}"))?;
            let secret = items::otp_secret(&vault, name)?;
            let totp = stash_core::otp::Totp::parse(&secret)
                .with_context(|| format!("{name} isn't a 2FA secret"))?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let code = Zeroizing::new(totp.code_at(now));
            if copy {
                copy_to_clipboard(code.as_bytes(), &format!("the code for {name}"))?;
            } else {
                print_secret(code.as_bytes())?;
            }
            ui::success(&format!("valid for {}s", totp.remaining(now)));
        }
        Command::Ls { long } => {
            let vault = unlock(&path, "list secret names")?;
            if long {
                items::list_long(&vault)?;
            } else {
                let mut out = io::stdout().lock();
                for name in vault.names()? {
                    writeln!(out, "{name}")?;
                }
            }
        }
        Command::Rm { name } => {
            let mut vault = unlock(&path, &format!("remove {name}"))?;
            vault.remove(&name)?;
            eprintln!("Removed {name}");
        }
        Command::Run {
            env_files,
            no_masking,
            command,
        } => {
            let opts = run::Options {
                env_files,
                no_masking,
                command,
            };
            return run::run(opts, |purpose| unlock(&path, purpose));
        }
        Command::Inject {
            input,
            output,
            force,
        } => {
            let opts = inject::Options {
                input,
                output,
                force,
            };
            inject::inject(opts, |purpose| unlock(&path, purpose))?;
        }
        Command::Mcp {
            allow,
            allow_reveal,
            no_approval,
        } => {
            for pattern in &allow {
                if pattern.is_empty() {
                    bail!("--allow patterns can't be empty");
                }
            }
            let opts = mcp::Options {
                allow,
                allow_reveal,
                no_approval,
                idle_timeout: session_timeout()?.unwrap_or(Duration::ZERO),
            };
            mcp::serve(path, opts)?;
        }
        Command::Audit { limit } => {
            let events = audit::recent(&audit::path_for(&path), limit)?;
            if events.is_empty() {
                eprintln!("No AI-agent requests recorded yet.");
            }
            let mut out = io::stdout().lock();
            for event in &events {
                writeln!(out, "{}", audit::describe(event))?;
            }
        }
        Command::Lock => {
            if agent::lock(&agent::default_socket()?) {
                eprintln!("Locked");
            } else {
                eprintln!("Already locked");
            }
        }
        Command::TouchId { action } => touch_id(action, &path)?,
        Command::Agent { .. } | Command::ClipboardClear { .. } => unreachable!("handled above"),
    }
    Ok(ExitCode::SUCCESS)
}

/// Print a secret to stdout, with a newline only on a terminal so piped
/// output is the exact value.
fn print_secret(value: &[u8]) -> Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(value)?;
    if out.is_terminal() {
        out.write_all(b"\n")?;
    }
    out.flush()?;
    Ok(())
}

fn copy_to_clipboard(value: &[u8], what: &str) -> Result<()> {
    clipboard::copy(value)?;
    match clipboard::timeout()? {
        Some(after) => {
            clipboard::clear_later(value, after)?;
            ui::success(&format!("copied {what} · clears in {}s", after.as_secs()));
        }
        None => ui::success(&format!("copied {what}")),
    }
    Ok(())
}

fn touch_id(action: TouchIdAction, path: &Path) -> Result<()> {
    let helper = touchid::helper();
    match action {
        TouchIdAction::Enable => {
            let helper = helper.context(
                "the stash-touchid helper was not found; see the README for how to install it",
            )?;
            // Always require the master password to turn on a new way in.
            let vault = unlock_with_password(path, "turn on Touch ID")?;
            touchid::enroll(&helper, path, vault.key())?;
            eprintln!("Touch ID unlock is on");
        }
        TouchIdAction::Disable => {
            if touchid::disable(path)? {
                agent::lock(&agent::default_socket()?);
                eprintln!("Touch ID unlock is off");
            } else {
                eprintln!("Touch ID unlock was not on");
            }
        }
        TouchIdAction::Status => {
            let available = match &helper {
                None => "no (stash-touchid helper not found)".to_owned(),
                Some(helper) => match touchid::availability(helper) {
                    Ok(()) => "yes".to_owned(),
                    Err(why) => format!("no ({why})"),
                },
            };
            println!("Touch ID available: {available}");
            let enabled = if touchid::is_enrolled(path) {
                "yes"
            } else {
                "no"
            };
            println!("Touch ID unlock on: {enabled}");
        }
    }
    Ok(())
}

fn default_vault_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not find your home directory; pass --vault")?;
    Ok(home.join(".stash").join("vault.db"))
}

/// Unlock in order of convenience: an existing session, then Touch ID, then
/// the master password. A fresh unlock starts a session.
///
/// Sessions belong to the process that ran `stash` (see `agent.rs`), so only
/// later commands from that same parent reuse one. `purpose` describes the
/// request in the Touch ID and password prompts, along with who is asking.
///
/// `STASH_PASSWORD` skips sessions and Touch ID entirely, so scripts never
/// start background processes or show prompts.
fn unlock(path: &Path, purpose: &str) -> Result<Vault> {
    if std::env::var_os(PASSWORD_ENV).is_some() {
        return unlock_with_password(path, purpose);
    }
    if !path.exists() {
        return Err(stash_core::Error::VaultMissing(path.to_owned()).into());
    }
    let canonical = path.canonicalize()?;
    let session = session_timeout()?;
    let socket = agent::default_socket()?;

    if session.is_some()
        && let Some(key) = agent::get(&socket, &canonical)
        && let Ok(vault) = Vault::open_with_key(path, &key)
    {
        return Ok(vault);
    }

    let vault = match unlock_with_touch_id(path, purpose)? {
        Some(vault) => vault,
        None => unlock_with_password(path, purpose)?,
    };
    if let Some(idle) = session
        && let Err(e) = agent::put(&socket, &canonical, vault.key(), idle)
    {
        eprintln!("stash: warning: could not start a session ({e:#}); you'll be asked again");
    }
    Ok(vault)
}

/// `Ok(None)` means "fall back to the master password".
fn unlock_with_touch_id(path: &Path, purpose: &str) -> Result<Option<Vault>> {
    if !touchid::is_enrolled(path) {
        return Ok(None);
    }
    let Some(helper) = touchid::helper() else {
        eprintln!("stash: Touch ID helper not found; using the master password");
        return Ok(None);
    };
    let reason = format!(
        "unlock stash for “{purpose}”, requested by {}",
        procinfo::requester_chain(2)
    );
    let why = match touchid::unlock(&helper, path, &reason) {
        Ok(key) => match Vault::open_with_key(path, &key) {
            Ok(vault) => return Ok(Some(vault)),
            Err(stash_core::Error::WrongKey) => {
                "Touch ID data doesn't match this vault; run `stash touchid enable` again".into()
            }
            Err(e) => return Err(e.into()),
        },
        Err(touchid::UnlockError::Cancelled) => "Touch ID was cancelled".into(),
        Err(touchid::UnlockError::Unavailable(why)) => why,
        Err(touchid::UnlockError::Failed(why)) => format!("Touch ID failed: {why}"),
    };
    eprintln!("stash: {why}; using the master password");
    Ok(None)
}

fn unlock_with_password(path: &Path, purpose: &str) -> Result<Vault> {
    let password = match std::env::var(PASSWORD_ENV) {
        Ok(password) => Zeroizing::new(password),
        Err(_) => {
            if !path.exists() {
                return Err(stash_core::Error::VaultMissing(path.to_owned()).into());
            }
            eprintln!(
                "stash: unlocking for “{purpose}”, requested by {}",
                procinfo::requester_chain(2)
            );
            Zeroizing::new(rpassword::prompt_password("Master password: ")?)
        }
    };
    Ok(Vault::open(path, password.as_bytes())?)
}

fn session_timeout() -> Result<Option<Duration>> {
    match std::env::var(SESSION_TIMEOUT_ENV) {
        Err(_) => Ok(Some(DEFAULT_SESSION_TIMEOUT)),
        Ok(value) => {
            let secs: u64 = value
                .trim()
                .parse()
                .with_context(|| format!("{SESSION_TIMEOUT_ENV} must be a number of seconds"))?;
            Ok((secs > 0).then(|| Duration::from_secs(secs)))
        }
    }
}

fn new_password() -> Result<Zeroizing<String>> {
    let password = match std::env::var(PASSWORD_ENV) {
        Ok(password) => Zeroizing::new(password),
        Err(_) => {
            let first = Zeroizing::new(rpassword::prompt_password("New master password: ")?);
            let second = Zeroizing::new(rpassword::prompt_password("Confirm master password: ")?);
            if first != second {
                bail!("passwords do not match");
            }
            first
        }
    };
    if password.chars().count() < MIN_PASSWORD_LEN {
        bail!("master password must be at least {MIN_PASSWORD_LEN} characters");
    }
    Ok(password)
}

/// Prompt without echo on a terminal; otherwise read all of stdin, dropping
/// one trailing newline so `echo token | stash add name` stores `token`.
fn read_value(name: &str) -> Result<Zeroizing<Vec<u8>>> {
    read_input(&format!("Value for {name}: "))
}

pub(crate) fn stdin_is_terminal() -> bool {
    io::stdin().is_terminal()
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A hidden prompt on a terminal; otherwise all of stdin, minus one trailing
/// newline.
pub(crate) fn read_input(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        let value = Zeroizing::new(rpassword::prompt_password(prompt)?);
        if value.is_empty() {
            bail!("value is empty");
        }
        return Ok(Zeroizing::new(value.as_bytes().to_vec()));
    }
    let mut value = Zeroizing::new(Vec::new());
    stdin.lock().read_to_end(&mut value)?;
    if value.ends_with(b"\n") {
        value.pop();
        if value.ends_with(b"\r") {
            value.pop();
        }
    }
    Ok(value)
}
