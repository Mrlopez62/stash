//! Trusted files: a `.env` file (for `stash run`) or a template (for
//! `stash inject`) decides which of your secrets a command gets. In a
//! repository you cloned, someone else wrote that file. So the first time a
//! file asks for secrets, and whenever the secrets it asks for change, stash
//! asks for a fresh Touch ID or the master password, naming the file and
//! the secrets, even if this shell has an unlocked session. Like direnv's
//! `allow`.
//!
//! Approvals are kept in `vault.db.trusted` next to the vault, as one tag per
//! line: an HMAC, under a key only the unlocked vault has, of the file's
//! path and the references in it. So the list reveals no paths or names,
//! and a program running as you can't add an approval (only delete them,
//! which just means being asked again).

use std::collections::BTreeSet;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use stash_core::{Vault, reference};

use crate::{Unlocked, envfile, filelock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A `.env` file for `stash run`.
    Env,
    /// A template for `stash inject`.
    Template,
}

/// A file and the references it holds, as approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    kind: Kind,
    /// The canonical path, so `./.env` and `../app/.env` are the same file.
    pub path: PathBuf,
    /// Sorted: `VAR=stash://name` for `.env` files, `stash://name` for
    /// templates. Changing any of them needs a new approval.
    references: BTreeSet<String>,
    /// Secret names as shown in prompts.
    pub names: Vec<String>,
}

impl Request {
    /// What `contents` (read from `path`) asks for. `None` if it asks for
    /// no secrets, so there's nothing to approve.
    pub fn new(kind: Kind, path: &Path, contents: &str) -> Result<Option<Self>> {
        let mut references = BTreeSet::new();
        let mut names = BTreeSet::new();
        match kind {
            Kind::Env => {
                for (key, value) in envfile::parse(contents)? {
                    if let Some(r) = reference::parse(&value)? {
                        references.insert(format!("{key}={r}"));
                        names.insert(r.describe());
                    }
                }
            }
            Kind::Template => {
                for p in reference::placeholders(contents)? {
                    references.insert(p.reference.to_string());
                    names.insert(p.reference.describe());
                }
            }
        }
        if references.is_empty() {
            return Ok(None);
        }
        let path = path
            .canonicalize()
            .with_context(|| format!("could not find {}", path.display()))?;
        Ok(Some(Self {
            kind,
            path,
            references,
            names: names.into_iter().collect(),
        }))
    }

    /// Read `path` and see what it asks for.
    #[cfg(test)]
    pub fn read(kind: Kind, path: &Path) -> Result<Option<Self>> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        Self::new(kind, path, &contents).with_context(|| path.display().to_string())
    }

    fn tag(&self, vault: &Vault) -> Result<String> {
        let mut data = b"stash/trusted-file/v1\0".to_vec();
        data.extend_from_slice(match self.kind {
            Kind::Env => b"env\0",
            Kind::Template => b"template\0",
        });
        data.extend_from_slice(self.path.as_os_str().as_bytes());
        for r in &self.references {
            data.push(0);
            data.extend_from_slice(r.as_bytes());
        }
        let tag = vault.trust_tag(&data)?;
        Ok(tag.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// The approval prompt's wording.
    pub fn describe(&self) -> String {
        format!(
            "{} ({})",
            self.path.display(),
            crate::run::summarize(&self.names.iter().map(String::as_str).collect::<Vec<_>>())
        )
    }
}

/// Make sure every file is approved. Files that are new or changed need a
/// fresh approval, which is then remembered: the unlock itself, if it was
/// fresh (its prompt must have named the files), or else `approve`, given
/// the prompt's wording.
pub fn ensure(
    unlocked: &mut Unlocked,
    requests: &[Request],
    action: &str,
    approve: impl FnOnce(&mut Vault, &str) -> Result<()>,
) -> Result<()> {
    let vault = &mut unlocked.vault;
    let mut new = Vec::new();
    for request in requests {
        if !is_trusted(vault, request)? {
            new.push(request);
        }
    }
    if new.is_empty() {
        return Ok(());
    }
    if !unlocked.fresh {
        let files: Vec<String> = new.iter().map(|r| r.describe()).collect();
        approve(vault, &format!("allow {} to {action}", files.join("; ")))
            .context("not allowed (approve it once with Touch ID or your master password, or run `stash trust <file>`)")?;
    }
    for request in new {
        remember(vault, request)?;
    }
    Ok(())
}

/// The approvals for one vault: `vault.db.trusted` next to `vault.db`.
pub fn file_for(vault: &Path) -> PathBuf {
    let mut name = vault.file_name().unwrap_or_default().to_owned();
    name.push(".trusted");
    vault.with_file_name(name)
}

fn tags(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

pub fn is_trusted(vault: &Vault, request: &Request) -> Result<bool> {
    let tag = request.tag(vault)?;
    Ok(tags(&file_for(vault.path())).contains(&tag))
}

/// Remember an approval. Call only after a fresh one.
pub fn remember(vault: &Vault, request: &Request) -> Result<()> {
    let tag = request.tag(vault)?;
    let path = file_for(vault.path());
    let mut file = filelock::open_locked(&path)?;
    if !tags(&path).contains(&tag) {
        file.write_all(format!("{tag}\n").as_bytes())?;
    }
    Ok(())
}

/// Forget the approval for the file as it is now. Whether there was one.
pub fn forget(vault: &Vault, request: &Request) -> Result<bool> {
    let tag = request.tag(vault)?;
    let path = file_for(vault.path());
    let _guard = filelock::open_locked(&path)?;
    let mut tags = tags(&path);
    let before = tags.len();
    tags.retain(|t| *t != tag);
    if tags.len() == before {
        return Ok(false);
    }
    let contents: String = tags.iter().map(|t| format!("{t}\n")).collect();
    filelock::replace(&path, contents.as_bytes())?;
    Ok(true)
}

/// A yes/no setting that only a fresh approval can turn on, kept as a tag
/// in the same list (so a program running as you can't turn it on, only
/// off). Off by default.
pub fn setting(vault: &Vault, name: &str) -> Result<bool> {
    let tag = setting_tag(vault, name)?;
    Ok(tags(&file_for(vault.path())).contains(&tag))
}

/// Turn a setting on (call only after a fresh approval) or off.
pub fn set_setting(vault: &Vault, name: &str, on: bool) -> Result<()> {
    let tag = setting_tag(vault, name)?;
    let path = file_for(vault.path());
    let mut file = filelock::open_locked(&path)?;
    let mut tags = tags(&path);
    if on {
        if !tags.contains(&tag) {
            file.write_all(format!("{tag}\n").as_bytes())?;
        }
    } else if tags.contains(&tag) {
        tags.retain(|t| *t != tag);
        let contents: String = tags.iter().map(|t| format!("{t}\n")).collect();
        filelock::replace(&path, contents.as_bytes())?;
    }
    Ok(())
}

fn setting_tag(vault: &Vault, name: &str) -> Result<String> {
    let mut data = b"stash/setting/v1\0".to_vec();
    data.extend_from_slice(name.as_bytes());
    let tag = vault.trust_tag(&data)?;
    Ok(tag.iter().map(|b| format!("{b:02x}")).collect())
}

/// Forget every approval (after the vault's keys change, they can't match
/// anyway).
pub fn forget_all(vault: &Path) {
    let _ = std::fs::remove_file(file_for(vault));
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn new_vault(dir: &TempDir, name: &str) -> Vault {
        Vault::create(
            &dir.path().join(name),
            b"password",
            stash_core::KdfParams {
                m_cost_kib: 8,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap()
    }

    #[test]
    fn approvals_cover_one_file_with_the_same_secrets() {
        let dir = TempDir::new().unwrap();
        let vault = new_vault(&dir, "vault.db");
        let env = dir.path().join(".env");
        std::fs::write(&env, "TOKEN=stash://github/token\nPORT=3000\n").unwrap();
        let request = Request::read(Kind::Env, &env).unwrap().unwrap();
        assert_eq!(request.names, vec!["github/token"]);
        assert!(!is_trusted(&vault, &request).unwrap());
        remember(&vault, &request).unwrap();
        assert!(is_trusted(&vault, &request).unwrap());

        // Plain values can change; the secrets it asks for can't.
        std::fs::write(&env, "TOKEN=stash://github/token\nPORT=4000\n").unwrap();
        assert!(is_trusted(&vault, &Request::read(Kind::Env, &env).unwrap().unwrap()).unwrap());
        for changed in [
            "TOKEN=stash://aws/secret\n",
            "OTHER=stash://github/token\n",
            "TOKEN=stash://github/token\nMORE=stash://bank/visa\n",
        ] {
            std::fs::write(&env, changed).unwrap();
            let r = Request::read(Kind::Env, &env).unwrap().unwrap();
            assert!(!is_trusted(&vault, &r).unwrap(), "{changed}");
        }

        // The same contents in another folder isn't approved.
        let other = dir.path().join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::write(other.join(".env"), "TOKEN=stash://github/token\n").unwrap();
        let elsewhere = Request::read(Kind::Env, &other.join(".env"))
            .unwrap()
            .unwrap();
        assert!(!is_trusted(&vault, &elsewhere).unwrap());

        // Nor in another vault (which keeps its own list), and the list
        // reveals nothing.
        let other = new_vault(&dir, "other.db");
        assert!(!is_trusted(&other, &request).unwrap());
        remember(&other, &request).unwrap();
        forget_all(other.path());
        assert!(is_trusted(&vault, &request).unwrap());
        let list = std::fs::read_to_string(file_for(vault.path())).unwrap();
        assert!(!list.contains("github") && !list.contains(".env"));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(file_for(vault.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        assert!(forget(&vault, &request).unwrap());
        assert!(!is_trusted(&vault, &request).unwrap());
        assert!(!forget(&vault, &request).unwrap());
    }

    #[test]
    fn files_without_references_need_no_approval() {
        let dir = TempDir::new().unwrap();
        let env = dir.path().join(".env");
        std::fs::write(&env, "PORT=3000\n").unwrap();
        assert!(Request::read(Kind::Env, &env).unwrap().is_none());
        let tpl = dir.path().join("config.tpl");
        std::fs::write(
            &tpl,
            "key: {{ stash://aws/key }}\nother: {{ stash://aws/key }}\n",
        )
        .unwrap();
        let request = Request::read(Kind::Template, &tpl).unwrap().unwrap();
        assert_eq!(request.names, vec!["aws/key"]);
    }
}
