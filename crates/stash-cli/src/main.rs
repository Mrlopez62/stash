mod agent;
mod touchid;

use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use secrecy::ExposeSecret;
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
    /// Store a secret (value is read from stdin, or prompted for without echo)
    Add {
        /// Secret name, e.g. `github/token`
        name: String,
        /// Overwrite the secret if it already exists
        #[arg(long, short)]
        force: bool,
    },
    /// Print a secret's value
    Get {
        /// Secret name, e.g. `github/token`
        name: String,
    },
    /// List secret names (never values)
    #[command(alias = "list")]
    Ls,
    /// Delete a secret
    #[command(alias = "remove")]
    Rm {
        /// Secret name, e.g. `github/token`
        name: String,
    },
    /// End the unlocked session, so the next command asks again
    Lock,
    /// Unlock with your fingerprint instead of the master password (macOS)
    #[command(name = "touchid")]
    TouchId {
        #[command(subcommand)]
        action: TouchIdAction,
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
const PASSWORD_ENV: &str = "STASH_PASSWORD";
const MIN_PASSWORD_LEN: usize = 8;
/// Seconds an unlocked session lasts without use. `0` turns sessions off.
const SESSION_TIMEOUT_ENV: &str = "STASH_SESSION_TIMEOUT";
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(10 * 60);

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("stash: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    if let Command::Agent { socket } = &cli.command {
        return agent::serve(socket);
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
        Command::Add { name, force } => {
            stash_core::validate_name(&name)?;
            let mut vault = unlock(&path)?;
            let value = read_value(&name)?;
            vault.add(&name, &value, force)?;
            eprintln!("Saved {name}");
        }
        Command::Get { name } => {
            let vault = unlock(&path)?;
            let value = vault.get(&name)?;
            let mut out = io::stdout().lock();
            out.write_all(value.expose_secret())?;
            if out.is_terminal() {
                out.write_all(b"\n")?;
            }
            out.flush()?;
        }
        Command::Ls => {
            let vault = unlock(&path)?;
            let mut out = io::stdout().lock();
            for name in vault.names()? {
                writeln!(out, "{name}")?;
            }
        }
        Command::Rm { name } => {
            let mut vault = unlock(&path)?;
            vault.remove(&name)?;
            eprintln!("Removed {name}");
        }
        Command::Lock => {
            if agent::lock(&agent::default_socket()?) {
                eprintln!("Locked");
            } else {
                eprintln!("Already locked");
            }
        }
        Command::TouchId { action } => touch_id(action, &path)?,
        Command::Agent { .. } => unreachable!("handled above"),
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
            let vault = unlock_with_password(path)?;
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
/// `STASH_PASSWORD` skips sessions and Touch ID entirely, so scripts never
/// start background processes or show prompts.
fn unlock(path: &Path) -> Result<Vault> {
    if std::env::var_os(PASSWORD_ENV).is_some() {
        return unlock_with_password(path);
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

    let vault = match unlock_with_touch_id(path)? {
        Some(vault) => vault,
        None => unlock_with_password(path)?,
    };
    if let Some(idle) = session
        && let Err(e) = agent::put(&socket, &canonical, vault.key(), idle)
    {
        eprintln!("stash: warning: could not start a session ({e:#}); you'll be asked again");
    }
    Ok(vault)
}

/// `Ok(None)` means "fall back to the master password".
fn unlock_with_touch_id(path: &Path) -> Result<Option<Vault>> {
    if !touchid::is_enrolled(path) {
        return Ok(None);
    }
    let Some(helper) = touchid::helper() else {
        eprintln!("stash: Touch ID helper not found; using the master password");
        return Ok(None);
    };
    let why = match touchid::unlock(&helper, path) {
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

fn unlock_with_password(path: &Path) -> Result<Vault> {
    let password = match std::env::var(PASSWORD_ENV) {
        Ok(password) => Zeroizing::new(password),
        Err(_) => {
            if !path.exists() {
                return Err(stash_core::Error::VaultMissing(path.to_owned()).into());
            }
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
    let stdin = io::stdin();
    if stdin.is_terminal() {
        let value = Zeroizing::new(rpassword::prompt_password(format!("Value for {name}: "))?);
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
