//! `stash inject`: fill `{{ stash://name }}` placeholders in a template, so
//! config files can be generated from a committed template without the
//! secrets ever being committed.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use secrecy::ExposeSecret;
use stash_core::{Vault, reference};
use zeroize::Zeroizing;

use crate::ui;

pub struct Options {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub force: bool,
}

pub fn inject(opts: Options, unlock: impl FnOnce() -> Result<Vault>) -> Result<()> {
    let template = match &opts.input {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?,
        None => {
            let mut s = String::new();
            io::stdin()
                .read_to_string(&mut s)
                .context("could not read the template from stdin")?;
            s
        }
    };
    if let Some(path) = &opts.output
        && path.exists()
        && !opts.force
    {
        bail!(
            "{} already exists (use --force to overwrite)",
            path.display()
        );
    }

    let placeholders = reference::placeholders(&template)?;
    let mut rendered = Zeroizing::new(Vec::with_capacity(template.len()));
    if placeholders.is_empty() {
        rendered.extend_from_slice(template.as_bytes());
    } else {
        let vault = unlock()?;
        let mut last = 0;
        for placeholder in &placeholders {
            let value = vault
                .get(placeholder.name)
                .with_context(|| format!("resolving {{{{ stash://{} }}}}", placeholder.name))?;
            rendered.extend_from_slice(&template.as_bytes()[last..placeholder.span.start]);
            rendered.extend_from_slice(value.expose_secret());
            last = placeholder.span.end;
        }
        rendered.extend_from_slice(&template.as_bytes()[last..]);
    }

    match &opts.output {
        None => {
            let mut out = io::stdout().lock();
            out.write_all(&rendered)?;
            out.flush()?;
        }
        Some(path) => {
            // The output holds secrets: only you can read it.
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("could not write {}", path.display()))?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            file.write_all(&rendered)?;
            let n = placeholders.len();
            let plural = if n == 1 { "" } else { "s" };
            ui::success(&format!(
                "injected {n} secret{plural} into {}",
                path.display()
            ));
        }
    }
    Ok(())
}
