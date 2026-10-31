//! `stash export --phone FILE`: a separate vault, for the stash iPhone app,
//! with only your cards and bank accounts in it, and your logins if you ask
//! with `--logins`.
//!
//! It's a normal encrypted vault (same format, same Argon2id and sealing),
//! under its own password, so a lost phone holds no notes or SSH keys, and no
//! logins unless you chose to bring them, and its password needn't be your
//! master password. Writing it needs
//! a fresh Touch ID or the master password, since it copies every card.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use stash_core::{KdfParams, Kind, Vault};
use zeroize::Zeroizing;

use crate::{MIN_PASSWORD_LEN, Unlocked};

/// The extension the iPhone app opens (from Files, AirDrop, or Finder).
pub const PHONE_EXTENSION: &str = "stashvault";

pub struct Options {
    pub file: PathBuf,
    pub force: bool,
    /// Bring logins along too.
    pub logins: bool,
}

pub fn export_phone(
    opts: Options,
    unlock: impl FnOnce(&str) -> Result<Unlocked>,
    approve: impl FnOnce(&mut Vault, &str) -> Result<()>,
) -> Result<()> {
    if opts.file.extension().and_then(|e| e.to_str()) != Some(PHONE_EXTENSION) {
        bail!(
            "name the file with a .{PHONE_EXTENSION} extension (like phone.{PHONE_EXTENSION}), so the iPhone app can open it"
        );
    }
    if opts.file.exists() && !opts.force {
        bail!(
            "{} already exists (use --force to replace it)",
            opts.file.display()
        );
    }

    // The path goes in an approval prompt, so it can't be allowed to disguise itself.
    let what = if opts.logins {
        "cards, bank accounts, and logins"
    } else {
        "cards and bank accounts"
    };
    let purpose = format!(
        "copy your {what} to {}",
        crate::text::clean(&opts.file.display().to_string(), 400)
    );
    let mut unlocked = unlock(&purpose)?;
    // Every card at once, into a new file: a session isn't enough.
    if !unlocked.fresh {
        approve(&mut unlocked.vault, &format!("allow stash to {purpose}"))?;
    }
    let mut vault = unlocked.vault;
    crate::ensure_sensitive(&mut vault, &purpose)?;

    let mut items = Vec::new();
    for summary in vault.summaries()? {
        if matches!(summary.kind, Kind::Card | Kind::Bank)
            || (opts.logins && summary.kind == Kind::Login)
        {
            items.push((summary.name.clone(), vault.item(&summary.name)?));
        }
    }
    if items.is_empty() {
        bail!(
            "there are no {} to copy",
            if opts.logins {
                "cards, bank accounts, or logins"
            } else {
                "cards or bank accounts"
            }
        );
    }
    drop(vault);

    let password = phone_password()?;
    if opts.file.exists() {
        std::fs::remove_file(&opts.file)
            .with_context(|| format!("could not replace {}", opts.file.display()))?;
    }
    let mut phone = Vault::create(&opts.file, password.as_bytes(), KdfParams::default())?;
    for (name, item) in &items {
        phone.put(name, item, false)?;
    }
    let cards = items.iter().filter(|(_, i)| i.kind == Kind::Card).count();
    let logins = items.iter().filter(|(_, i)| i.kind == Kind::Login).count();
    let banks = items.len() - cards - logins;
    eprintln!(
        "Wrote {} with {cards} card{} and {banks} bank account{}{}.",
        opts.file.display(),
        if cards == 1 { "" } else { "s" },
        if banks == 1 { "" } else { "s" },
        match (opts.logins, logins) {
            (false, _) => String::new(),
            (true, 1) => ", and 1 login".to_owned(),
            (true, n) => format!(", and {n} logins"),
        },
    );
    eprintln!(
        "AirDrop it to your iPhone (or drag it onto the iPhone in Finder → Files → stash), open it in stash, and delete this copy."
    );
    Ok(())
}

/// The phone vault's password: `STASH_NEW_PASSWORD`, or asked for twice.
fn phone_password() -> Result<Zeroizing<String>> {
    let password = match std::env::var("STASH_NEW_PASSWORD") {
        Ok(p) => Zeroizing::new(p),
        Err(_) => {
            eprintln!(
                "Choose a password for the phone vault. It can differ from your master password; you'll type it once on the phone, then use Face ID."
            );
            let first = Zeroizing::new(rpassword::prompt_password("Phone vault password: ")?);
            let second = Zeroizing::new(rpassword::prompt_password(
                "Confirm phone vault password: ",
            )?);
            if first != second {
                bail!("passwords do not match");
            }
            first
        }
    };
    if password.chars().count() < MIN_PASSWORD_LEN {
        bail!("the password must be at least {MIN_PASSWORD_LEN} characters");
    }
    Ok(password)
}
