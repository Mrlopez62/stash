//! `stash import`: bring logins, notes, cards, and bank accounts over from
//! another password manager's export file.
//!
//! The export holds every password in plain text, so: it's read once into
//! memory that's wiped after, nothing else is written to disk, adding the
//! items takes a fresh Touch ID or the master password (never a session,
//! since it writes many items at once), and stash offers to delete the file
//! afterwards. Nothing in the vault is ever overwritten: a name that's taken
//! gets a `-2` suffix, unless the existing item is identical, which is then
//! left alone.

use std::collections::HashSet;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use stash_core::import::{self, Entry};
use stash_core::{Item, Vault};
use zeroize::Zeroizing;

use crate::Unlocked;

/// Exports bigger than this aren't password exports.
const MAX_SIZE: u64 = 64 * 1024 * 1024;

pub struct Options {
    pub file: PathBuf,
    pub dry_run: bool,
    pub delete_file: bool,
}

pub fn import(
    opts: Options,
    unlock: impl FnOnce(&str) -> Result<Unlocked>,
    approve: impl FnOnce(&mut Vault, &str) -> Result<()>,
) -> Result<()> {
    let size = std::fs::metadata(&opts.file)
        .with_context(|| format!("could not read {}", opts.file.display()))?
        .len();
    if size > MAX_SIZE {
        bail!("{} is too big to be a password export", opts.file.display());
    }
    let bytes = Zeroizing::new(
        std::fs::read(&opts.file)
            .with_context(|| format!("could not read {}", opts.file.display()))?,
    );
    let found = import::read(&bytes)?;
    drop(bytes);

    let summary = import::summarize(found.entries.iter().map(|e| &e.item));
    eprintln!(
        "Found {} item{} in this {} export{}",
        found.entries.len(),
        if found.entries.len() == 1 { "" } else { "s" },
        found.format,
        if summary.is_empty() {
            String::new()
        } else {
            format!(": {summary}")
        }
    );
    for skipped in &found.skipped {
        eprintln!(
            "  skipping “{}”: {}",
            crate::text::clean(&skipped.title, 60),
            skipped.why
        );
    }
    for entry in &found.entries {
        for warning in &entry.warnings {
            eprintln!("  “{}”: {warning}", crate::text::clean(&entry.title, 60));
        }
    }
    if opts.dry_run {
        let mut out = std::io::stdout().lock();
        for entry in &found.entries {
            writeln!(
                out,
                "{:<40} {:<13} ← {}",
                entry.name,
                kind_name(&entry.item),
                crate::text::clean(&entry.title, 60)
            )?;
        }
        eprintln!(
            "Nothing was imported (--dry-run). Names already in your vault would get a -2 suffix."
        );
        return Ok(());
    }
    if found.entries.is_empty() {
        bail!("there's nothing to import in {}", opts.file.display());
    }

    let purpose = format!("import {summary} from {}", opts.file.display());
    let mut unlocked = unlock(&purpose)?;
    // Many items at once, from a file: a session isn't enough.
    if !unlocked.fresh {
        approve(&mut unlocked.vault, &format!("allow stash to {purpose}"))?;
    }
    let mut vault = unlocked.vault;
    // Cards and bank accounts need the sensitive key. If that's declined,
    // import the rest and say what was left out.
    let mut held_back = 0;
    if found.entries.iter().any(|e| e.item.kind.is_sensitive())
        && let Err(e) = crate::ensure_sensitive(&mut vault, &purpose)
    {
        held_back = found
            .entries
            .iter()
            .filter(|e| e.item.kind.is_sensitive())
            .count();
        eprintln!("stash: leaving out {held_back} card(s) and bank account(s): {e:#}");
    }
    let entries = found
        .entries
        .iter()
        .filter(|e| held_back == 0 || !e.item.kind.is_sensitive());

    let outcome = add_all(&mut vault, entries)?;
    let Outcome {
        added,
        same,
        renamed,
        failed,
    } = &outcome;

    eprintln!(
        "Imported {} item{}{}",
        added.len(),
        if added.len() == 1 { "" } else { "s" },
        if added.is_empty() {
            String::new()
        } else {
            format!(": {}", import::summarize(added.iter().map(|e| &e.item)))
        }
    );
    if *same > 0 {
        eprintln!("  {same} already in your vault, unchanged");
    }
    for (wanted, got) in renamed {
        eprintln!("  {wanted} was taken, so it's {got}");
    }
    if held_back > 0 {
        eprintln!(
            "  {held_back} card(s) and bank account(s) left out; run the import again to add them"
        );
    }
    for (title, why) in failed {
        eprintln!("  couldn't add “{}”: {why}", crate::text::clean(title, 60));
    }
    drop(vault);

    offer_to_delete(&opts)?;
    if !failed.is_empty() {
        bail!("{} item(s) couldn't be imported", failed.len());
    }
    Ok(())
}

/// What adding a batch of entries did.
pub(crate) struct Outcome<'a> {
    pub added: Vec<&'a Entry>,
    /// Identical items already in the vault, left alone.
    pub same: usize,
    /// Suggested name → name used, when the suggestion was taken.
    pub renamed: Vec<(String, String)>,
    /// Title → why it couldn't be added.
    pub failed: Vec<(String, String)>,
}

/// Add entries to the vault, never overwriting: a taken name gets `-2`,
/// `-3`... unless the item there is identical (then it's left as is).
/// Cards and bank accounts need the sensitive key unlocked.
pub(crate) fn add_all<'a>(
    vault: &mut Vault,
    entries: impl IntoIterator<Item = &'a Entry>,
) -> Result<Outcome<'a>> {
    let mut outcome = Outcome {
        added: Vec::new(),
        same: 0,
        renamed: Vec::new(),
        failed: Vec::new(),
    };
    let mut taken = HashSet::new();
    for entry in entries {
        match place(vault, entry, &taken)? {
            Place::Same => outcome.same += 1,
            Place::Name(name) => match vault.put(&name, &entry.item, false) {
                Ok(()) => {
                    if name != entry.name {
                        outcome.renamed.push((entry.name.clone(), name.clone()));
                    }
                    taken.insert(name);
                    outcome.added.push(entry);
                }
                Err(e) => outcome.failed.push((entry.title.clone(), e.to_string())),
            },
        }
    }
    Ok(outcome)
}

enum Place {
    /// An identical item already has this name.
    Same,
    Name(String),
}

/// The name to save under: the suggested one, or with `-2`, `-3`... if it's
/// taken by a different item.
fn place(vault: &Vault, entry: &Entry, taken: &HashSet<String>) -> Result<Place> {
    for n in 1..1000 {
        let name = if n == 1 {
            entry.name.clone()
        } else {
            format!("{}-{n}", entry.name)
        };
        if stash_core::validate_name(&name).is_err() {
            continue;
        }
        if taken.contains(&name) {
            continue;
        }
        if !vault.contains(&name)? {
            return Ok(Place::Name(name));
        }
        // Checked at every taken name, so importing the same file again
        // finds `github-2` from last time instead of adding `github-3`.
        if same_item(&vault.item(&name)?, &entry.item) {
            return Ok(Place::Same);
        }
    }
    bail!("no free name for {}", entry.name)
}

/// The same kind, fields, and notes (timestamps aside).
fn same_item(a: &Item, b: &Item) -> bool {
    a.kind == b.kind
        && a.notes == b.notes
        && a.fields.len() == b.fields.len()
        && a.fields
            .iter()
            .zip(&b.fields)
            .all(|(x, y)| x.label == y.label && x.kind == y.kind && x.value == y.value)
}

fn kind_name(item: &Item) -> &'static str {
    match item.kind {
        stash_core::Kind::Login => "login",
        stash_core::Kind::Secret => "secret",
        stash_core::Kind::Note => "note",
        stash_core::Kind::Card => "card",
        stash_core::Kind::Bank => "bank account",
        stash_core::Kind::Ssh => "SSH key",
    }
}

/// The export holds every password in plain text: offer to delete it.
fn offer_to_delete(opts: &Options) -> Result<()> {
    let delete = if opts.delete_file {
        true
    } else if std::io::stdin().is_terminal() {
        eprint!(
            "{} holds all those passwords in plain text. Delete it now? [y/N] ",
            opts.file.display()
        );
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        matches!(answer.trim(), "y" | "Y" | "yes")
    } else {
        eprintln!(
            "Delete {} when you're done: it holds those passwords in plain text (or pass --delete-file).",
            opts.file.display()
        );
        false
    };
    if delete {
        std::fs::remove_file(&opts.file)
            .with_context(|| format!("could not delete {}", opts.file.display()))?;
        eprintln!("Deleted {}", opts.file.display());
    }
    Ok(())
}
