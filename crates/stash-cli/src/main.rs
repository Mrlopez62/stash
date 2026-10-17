use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
}

/// Read from the environment instead of prompting. Meant for scripts and CI:
/// anything that can read your environment can read this password.
const PASSWORD_ENV: &str = "STASH_PASSWORD";
const MIN_PASSWORD_LEN: usize = 8;

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
    let path = match cli.vault {
        Some(path) => path,
        None => default_vault_path()?,
    };

    match cli.command {
        Command::Init => {
            let password = new_password()?;
            Vault::create(&path, password.as_bytes(), KdfParams::default())?;
            eprintln!("Created vault at {}", path.display());
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
    }
    Ok(())
}

fn default_vault_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not find your home directory; pass --vault")?;
    Ok(home.join(".stash").join("vault.db"))
}

fn unlock(path: &Path) -> Result<Vault> {
    let password = match std::env::var(PASSWORD_ENV) {
        Ok(password) => Zeroizing::new(password),
        Err(_) => Zeroizing::new(rpassword::prompt_password("Master password: ")?),
    };
    Ok(Vault::open(path, password.as_bytes())?)
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
