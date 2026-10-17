//! Commands for structured items: logins, notes, editing, showing, and
//! generating passwords.
//!
//! Non-secret values (username, website, custom text fields) can be given
//! as flags. Secret ones (passwords, 2FA secrets, notes) are only ever read
//! from a hidden prompt or stdin, so they stay out of shell history.

use std::io::{self, Write};

use anyhow::{Context, Result, bail};
use clap::Args;
use stash_core::generate::{self, Rules};
use stash_core::item::{FieldValue, ONE_TIME_PASSWORD, PASSWORD, USERNAME, WEBSITE};
use stash_core::otp::Totp;
use stash_core::{FieldKind, Item, Kind, Vault};
use zeroize::{Zeroize, Zeroizing};

use crate::{read_input, stdin_is_terminal, ui};

#[derive(Args, Debug, Clone)]
pub struct GenerateArgs {
    /// Password length
    #[arg(long, default_value_t = 24)]
    pub length: usize,
    /// Leave out symbols
    #[arg(long)]
    pub no_symbols: bool,
    /// Leave out digits
    #[arg(long)]
    pub no_digits: bool,
    /// Leave out uppercase letters
    #[arg(long)]
    pub no_uppercase: bool,
}

impl GenerateArgs {
    pub fn rules(&self) -> Rules {
        Rules {
            length: self.length,
            uppercase: !self.no_uppercase,
            digits: !self.no_digits,
            symbols: !self.no_symbols,
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct LoginArgs {
    /// Username or email
    #[arg(long)]
    pub username: Option<String>,
    /// Website, e.g. https://github.com
    #[arg(long)]
    pub url: Option<String>,
    /// Add a 2FA secret (asked for without echo: paste the otpauth:// URI or
    /// base32 secret)
    #[arg(long)]
    pub otp: bool,
    /// Generate a random password instead of typing one
    #[arg(long)]
    pub generate: bool,
    #[command(flatten)]
    pub rules: GenerateArgs,
}

fn read_otp() -> Result<Zeroizing<String>> {
    let secret = read_text("2FA secret (otpauth:// URI or base32): ")?;
    Totp::parse_new(&secret).context("that isn't a 2FA secret")?;
    Ok(secret)
}

fn read_text(prompt: &str) -> Result<Zeroizing<String>> {
    let bytes = read_input(prompt)?;
    let text = String::from_utf8(bytes.to_vec()).context("the value must be text")?;
    Ok(Zeroizing::new(text))
}

fn new_password(login: &LoginArgs) -> Result<Zeroizing<String>> {
    if login.generate {
        let pw = generate::password(login.rules.rules())?;
        ui::success(&format!(
            "generated a {}-character password",
            login.rules.length
        ));
        Ok(pw)
    } else {
        read_text("Password: ")
    }
}

/// Only one secret can come from piped stdin.
fn check_one_piped_secret(needs_password: bool, otp: bool) -> Result<()> {
    if needs_password && otp && !stdin_is_terminal() {
        bail!(
            "stdin can supply either the password or the 2FA secret, not both; \
             use --generate, or add 2FA afterwards with `stash edit <name> --otp`"
        );
    }
    Ok(())
}

/// Checks to run before asking for any secret, so you're never made to type
/// a password only to hit an error.
fn check_can_add(vault: &Vault, name: &str, force: bool, structured: bool) -> Result<()> {
    if !force && vault.contains(name)? {
        bail!("{name} already exists (use --force to overwrite)");
    }
    if structured && !vault.is_current() {
        return Err(vault.upgrade_error().into());
    }
    Ok(())
}

pub fn add_login(vault: &mut Vault, name: &str, login: &LoginArgs, force: bool) -> Result<()> {
    check_can_add(vault, name, force, true)?;
    check_one_piped_secret(!login.generate, login.otp)?;
    let password = new_password(login)?;
    let mut item = Item::login(login.username.as_deref(), &password, login.url.as_deref());
    if login.otp {
        item.set(ONE_TIME_PASSWORD, FieldKind::Otp, read_otp()?.as_str());
    }
    vault.put(name, &item, force)?;
    eprintln!("Saved login {name}");
    Ok(())
}

pub fn add_note(vault: &mut Vault, name: &str, force: bool) -> Result<()> {
    check_can_add(vault, name, force, true)?;
    let text = read_text("Note: ")?;
    vault.put(name, &Item::note(text.as_str()), force)?;
    eprintln!("Saved note {name}");
    Ok(())
}

#[derive(Args, Debug, Clone)]
pub struct EditArgs {
    #[command(flatten)]
    pub login: LoginArgs,
    /// Read a new password (or a secret's new value) from a prompt or stdin
    #[arg(long, conflicts_with = "generate")]
    pub password: bool,
    /// Set a visible text field (repeatable)
    #[arg(long, value_name = "LABEL=VALUE")]
    pub set: Vec<String>,
    /// Remove a field (repeatable)
    #[arg(long, value_name = "LABEL")]
    pub unset: Vec<String>,
    /// Replace the notes (read from a prompt or stdin)
    #[arg(long)]
    pub notes: bool,
}

pub fn edit(vault: &mut Vault, name: &str, args: &EditArgs) -> Result<()> {
    let login = &args.login;
    let changes_password = args.password || login.generate;
    // Username, website, and 2FA make an item a login. Custom fields (--set)
    // don't: an API token with a `scope` field is still a secret.
    let touches_login = login.username.is_some() || login.url.is_some() || login.otp;
    let inputs = [changes_password && !login.generate, login.otp, args.notes];
    if inputs.iter().filter(|&&x| x).count() > 1 && !stdin_is_terminal() {
        bail!("only one of --password, --otp, and --notes can read from piped stdin at a time");
    }
    if !(changes_password
        || touches_login
        || !args.set.is_empty()
        || !args.unset.is_empty()
        || args.notes)
    {
        bail!("nothing to change (see `stash edit --help`)");
    }

    let mut item = vault.item(name)?;
    // Only a one-value, no-notes secret that stays that way can be saved in
    // a vault that hasn't been upgraded yet.
    let stays_plain_secret = item.kind == Kind::Secret
        && item.fields.len() == 1
        && item.notes.is_empty()
        && !touches_login
        && args.set.is_empty()
        && !args.notes
        && args.unset.is_empty();
    if !stays_plain_secret && !vault.is_current() {
        return Err(vault.upgrade_error().into());
    }
    // Checked up front so no secret is asked for before an error.
    for pair in &args.set {
        let label = pair
            .split_once('=')
            .map_or(pair.as_str(), |(l, _)| l)
            .trim();
        check_settable(&item, label)?;
    }
    // A secret's first field *is* its value: removing it would quietly make
    // the next field the secret.
    for label in &args.unset {
        let is_value = item.kind == Kind::Secret
            && item.labeled(label).is_some_and(|f| {
                std::ptr::eq(f, item.fields.first().expect("labeled found a field"))
            });
        if is_value {
            bail!("that's {name}'s value; to delete the item, use `stash rm {name}`");
        }
    }
    // A secret that gains login details becomes a login: its value becomes
    // the password, and its notes and any other fields are kept.
    if item.kind == Kind::Secret && touches_login {
        item.kind = Kind::Login;
        if let Some(first) = item.fields.first_mut() {
            first.label = PASSWORD.to_owned();
            first.kind = FieldKind::Concealed;
        }
    }
    if item.kind == Kind::Note && (changes_password || login.otp) {
        bail!("{name} is a note, which has no password or 2FA");
    }

    if changes_password {
        let password = new_password(login)?;
        match item.kind {
            // Replace the value in place, keeping notes and other fields.
            Kind::Secret => {
                let label = item
                    .fields
                    .first()
                    .map_or_else(|| "value".to_owned(), |f| f.label.clone());
                item.set(&label, FieldKind::Concealed, password.as_str());
            }
            _ => item.set(PASSWORD, FieldKind::Concealed, password.as_str()),
        }
    }
    if let Some(username) = &login.username {
        let kind = if username.contains('@') {
            FieldKind::Email
        } else {
            FieldKind::Text
        };
        item.set(USERNAME, kind, username.as_str());
    }
    if let Some(url) = &login.url {
        item.set(WEBSITE, FieldKind::Url, url.as_str());
    }
    if login.otp {
        item.set(ONE_TIME_PASSWORD, FieldKind::Otp, read_otp()?.as_str());
    }
    for pair in &args.set {
        let (label, value) = pair
            .split_once('=')
            .with_context(|| format!("--set expects LABEL=VALUE, got `{pair}`"))?;
        let label = label.trim();
        // Updating a visible field keeps its type (a website stays a URL).
        let kind = item.labeled(label).map_or(FieldKind::Text, |f| f.kind);
        item.set(label, kind, value);
    }
    for label in &args.unset {
        let before = item.fields.len();
        let wanted = item.labeled(label).map(|f| f.label.clone());
        item.fields.retain(|f| Some(&f.label) != wanted.as_ref());
        if item.fields.len() == before {
            bail!("{name} has no field `{label}`");
        }
    }
    if args.notes {
        let notes = read_text("Notes: ")?;
        item.notes.zeroize();
        item.notes = notes.to_string();
    }
    vault.put(name, &item, true)?;
    eprintln!("Updated {name}");
    Ok(())
}

/// `--set` puts its value on the command line, where shell history and
/// `ps` can see it, so it's only for visible fields. Secrets have their own
/// flags, which read from a prompt or stdin.
fn check_settable(item: &Item, label: &str) -> Result<()> {
    if label.is_empty() {
        bail!("--set needs a label");
    }
    let normalized: String = label
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '_'))
        .flat_map(char::to_lowercase)
        .collect();
    let hint = match normalized.as_str() {
        "password" | "pass" | "pw" | "passcode" | "pin" => Some("--password or --generate"),
        // Labels that almost always hold a secret. Store those as their own
        // secret item instead (`stash add <name>`), and reference it.
        "token" | "secret" | "apikey" | "apisecret" | "privatekey" | "secretkey" | "accesskey"
        | "clientsecret" => Some("a separate secret item (`stash add <name>`)"),
        "otp" | "totp" | "2fa" | "code" | "onetimepassword" => Some("--otp"),
        "notes" | "note" => Some("--notes"),
        _ => None,
    };
    let sensitive = item.labeled(label).is_some_and(|f| f.kind.is_sensitive());
    if let Some(hint) = hint.or(sensitive.then_some("--password or --otp")) {
        bail!(
            "`{label}` looks like a secret, and --set would put it in your shell history; \
             use {hint} instead, which reads from a hidden prompt or stdin"
        );
    }
    Ok(())
}

const HIDDEN: &str = "••••••••";

pub fn show(vault: &Vault, name: &str, reveal: bool) -> Result<()> {
    let item = vault.item(name)?;
    let mut out = io::stdout().lock();
    writeln!(out, "{name}  ({})", item.kind)?;
    let width = item
        .fields
        .iter()
        .map(|f| f.label.chars().count())
        .max()
        .unwrap_or(0)
        .max(8);
    let now = crate::unix_now();
    for field in &item.fields {
        // Revealed values are wiped once printed.
        let shown: Zeroizing<String> = Zeroizing::new(match (field.kind, reveal) {
            (FieldKind::Otp, true) => match Totp::parse(&field.value) {
                Ok(totp) => format!(
                    "{}  (valid for {}s)",
                    totp.code_at(now),
                    totp.remaining(now)
                ),
                Err(_) => "(invalid 2FA secret)".into(),
            },
            (FieldKind::Otp, false) => {
                format!("{HIDDEN}  (code with --reveal or `stash otp {name}`)")
            }
            (FieldKind::Concealed, false) => HIDDEN.into(),
            _ => field.value.clone(),
        });
        writeln!(out, "  {:<width$}  {}", field.label, shown.as_str())?;
    }
    if !item.notes.is_empty() {
        if reveal {
            writeln!(out, "  notes")?;
            for line in item.notes.lines() {
                writeln!(out, "    {line}")?;
            }
        } else {
            writeln!(out, "  {:<width$}  (hidden; --reveal to show)", "notes")?;
        }
    }
    if item.updated > 0 {
        writeln!(
            out,
            "  {:<width$}  {}",
            "updated",
            crate::audit::format_utc(item.updated)
        )?;
    }
    if !reveal && item.fields.iter().any(|f| f.kind.is_sensitive()) {
        writeln!(
            out,
            "\nUse --reveal to show hidden values, or `stash get {name}#<field>`."
        )?;
    }
    Ok(())
}

/// The OTP secret behind `stash otp <name>`: a secret's value, or a login's
/// one-time password field.
pub fn otp_secret(vault: &Vault, name: &str) -> Result<Zeroizing<String>> {
    let item = vault.item(name)?;
    let secret = match item.kind {
        Kind::Secret => item.primary().unwrap_or(""),
        _ => match item.field("otp") {
            Some(FieldValue::Otp(secret)) => secret,
            _ => bail!("{name} has no 2FA; add it with `stash edit {name} --otp`"),
        },
    };
    Ok(Zeroizing::new(secret.to_owned()))
}

pub fn list_long(vault: &Vault) -> Result<()> {
    let rows = vault.summaries()?;
    let name_w = rows.iter().map(|r| r.name.len()).max().unwrap_or(4).max(4);
    let user_w = rows
        .iter()
        .filter_map(|r| r.username.as_ref().map(|u| u.chars().count()))
        .max()
        .unwrap_or(8)
        .max(8);
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "{:<name_w$}  {:<6}  {:<user_w$}  {:<3}  WEBSITE",
        "NAME", "KIND", "USERNAME", "2FA"
    )?;
    for r in rows {
        writeln!(
            out,
            "{:<name_w$}  {:<6}  {:<user_w$}  {:<3}  {}",
            r.name,
            r.kind.to_string(),
            r.username.as_deref().unwrap_or(""),
            if r.has_otp { "yes" } else { "" },
            r.url.as_deref().unwrap_or("")
        )?;
    }
    Ok(())
}
