//! `stash inject`: fill `{{ stash://name }}` placeholders in a template, so
//! config files can be generated from a committed template without the
//! secrets ever being committed.

use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use stash_core::{Vault, reference};
use zeroize::Zeroizing;

use crate::ui;

pub struct Options {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub force: bool,
}

pub fn inject(opts: Options, unlock: impl FnOnce(&str) -> Result<Vault>) -> Result<()> {
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
        let described: Vec<String> = placeholders
            .iter()
            .map(|p| p.reference.describe())
            .collect();
        let names: Vec<&str> = described.iter().map(String::as_str).collect();
        let target = opts
            .output
            .as_ref()
            .map_or("stdout".to_owned(), |p| p.display().to_string());
        let vault = unlock(&format!(
            "inject {} into {target}",
            crate::run::summarize(&names)
        ))?;
        let now = crate::unix_now();
        let mut last = 0;
        for placeholder in &placeholders {
            let value = vault
                .resolve(&placeholder.reference, now)
                .with_context(|| format!("resolving {{{{ {} }}}}", placeholder.reference))?;
            rendered.extend_from_slice(&template.as_bytes()[last..placeholder.span.start]);
            rendered.extend_from_slice(&value);
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
            write_private(path, &rendered, opts.force)
                .with_context(|| format!("could not write {}", path.display()))?;
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

/// Write a file only you can read, all at once or not at all.
///
/// The data goes to a `0600` temp file in the same directory first, then
/// moves into place: with `overwrite` by rename (which replaces a symlink
/// rather than writing through it), otherwise by an exclusive hard link, so
/// an existing file is never clobbered even if one appears after our check.
fn write_private(path: &Path, data: &[u8], overwrite: bool) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .context("the output path has no file name")?;
    let tmp = dir.join(format!(
        ".{}.stash-{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));

    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        if overwrite {
            fs::rename(&tmp, path)?;
            return Ok(());
        }
        match fs::hard_link(&tmp, path) {
            Ok(()) => Ok(fs::remove_file(&tmp)?),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                bail!("it already exists (use --force to overwrite)")
            }
            // Filesystems without hard links: the earlier existence check is
            // the best we can do.
            Err(_) if !path.exists() => Ok(fs::rename(&tmp, path)?),
            Err(e) => Err(e.into()),
        }
    })();
    if tmp.exists() {
        let _ = fs::remove_file(&tmp);
    }
    result
}
