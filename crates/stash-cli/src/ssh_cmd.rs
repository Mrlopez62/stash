//! `stash ssh`: SSH keys in the vault, the agent that serves them, and git
//! commit signing with them.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use stash_core::ssh::KeyPair;
use stash_core::{Item, Kind, Vault};
use zeroize::Zeroizing;

use crate::ssh_agent;

const LAUNCH_AGENT_LABEL: &str = "dev.stash.ssh-agent";

pub fn generate(vault: &mut Vault, name: &str, comment: Option<&str>, force: bool) -> Result<()> {
    check_can_add(vault, name, force)?;
    let pair = KeyPair::generate(comment.unwrap_or(name))?;
    vault.put(name, &Item::ssh_key(&pair), force)?;
    eprintln!("Saved SSH key {name} ({})", pair.fingerprint());
    eprintln!(
        "Add this public key to GitHub (Settings → SSH and GPG keys) or a server's authorized_keys:"
    );
    println!("{}", pair.public_line());
    Ok(())
}

pub fn import(vault: &mut Vault, name: &str, file: &Path, force: bool) -> Result<()> {
    check_can_add(vault, name, force)?;
    let text = Zeroizing::new(
        fs::read_to_string(file).with_context(|| format!("could not read {}", file.display()))?,
    );
    let pair = match KeyPair::from_openssh(&text, None) {
        Err(stash_core::Error::SshPassphrase) => {
            let passphrase = Zeroizing::new(rpassword::prompt_password(format!(
                "Passphrase for {}: ",
                file.display()
            ))?);
            KeyPair::from_openssh(&text, Some(passphrase.as_bytes()))?
        }
        other => other?,
    };
    vault.put(name, &Item::ssh_key(&pair), force)?;
    eprintln!("Imported SSH key {name} ({})", pair.fingerprint());
    eprintln!(
        "The key is now in your vault. Once the stash agent works for you, you can delete {} \
         (keep a backup until then).",
        file.display()
    );
    Ok(())
}

fn check_can_add(vault: &Vault, name: &str, force: bool) -> Result<()> {
    if !force && vault.contains(name)? {
        bail!("{name} already exists (use --force to overwrite)");
    }
    if !vault.is_current() {
        return Err(vault.upgrade_error().into());
    }
    Ok(())
}

fn key_pair(vault: &Vault, name: &str) -> Result<KeyPair> {
    let item = vault.item(name)?;
    if item.kind != Kind::Ssh {
        bail!("{name} is a {}, not an SSH key", item.kind);
    }
    Ok(item.ssh_key_pair()?)
}

pub fn public(vault: &Vault, name: &str) -> Result<()> {
    println!("{}", key_pair(vault, name)?.public_line());
    Ok(())
}

pub fn list(vault: &Vault) -> Result<()> {
    let mut any = false;
    for summary in vault.summaries()? {
        if summary.kind == Kind::Ssh {
            any = true;
            println!("{}\t{}", summary.name, summary.subtitle.unwrap_or_default());
        }
    }
    if !any {
        eprintln!("No SSH keys yet. Make one with `stash ssh generate <name>`.");
    }
    Ok(())
}

/// "10m", "1h", "90s", or plain seconds.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let (number, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = number
        .parse()
        .with_context(|| format!("`{s}` isn't a duration (try 10m, 1h, or 600)"))?;
    let secs = match unit {
        "" | "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        _ => bail!("`{s}` isn't a duration (try 10m, 1h, or 600)"),
    };
    Ok(Duration::from_secs(secs))
}

pub fn agent(vault: &Path, socket: &Path, lock_after: Duration, no_approval: bool) -> Result<()> {
    if no_approval && std::env::var_os(crate::PASSWORD_ENV).is_none() {
        bail!(
            "--no-approval is only for headless use with {}",
            crate::PASSWORD_ENV
        );
    }
    if !vault.exists() {
        return Err(stash_core::Error::VaultMissing(vault.to_owned()).into());
    }
    let vault = vault.canonicalize()?;
    let agent = ssh_agent::Agent::new(
        vault,
        lock_after,
        ssh_agent::TouchIdGate {
            approve: !no_approval,
        },
    );
    ssh_agent::serve(socket, agent)
}

fn home() -> Result<PathBuf> {
    dirs::home_dir().context("could not find your home directory")
}

fn launch_agent_plist() -> Result<PathBuf> {
    Ok(home()?
        .join("Library/LaunchAgents")
        .join(format!("{LAUNCH_AGENT_LABEL}.plist")))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Start the agent at login with launchd, and print how to point SSH at it.
pub fn install(vault: &Path, socket: &Path, lock_after: Duration) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!(
            "`stash ssh install` sets up a macOS login item; elsewhere, run `stash ssh agent` from your session startup"
        );
    }
    if !vault.exists() {
        return Err(stash_core::Error::VaultMissing(vault.to_owned()).into());
    }
    let exe = std::env::current_exe()?.canonicalize()?;
    let vault = vault.canonicalize()?;
    let log = vault.with_file_name("ssh-agent.log");
    let args = [
        exe.to_string_lossy().into_owned(),
        "--vault".into(),
        vault.to_string_lossy().into_owned(),
        "ssh".into(),
        "agent".into(),
        "--socket".into(),
        socket.to_string_lossy().into_owned(),
        "--lock-after".into(),
        lock_after.as_secs().to_string(),
    ];
    let args_xml: String = args
        .iter()
        .map(|a| format!("        <string>{}</string>\n", xml_escape(a)))
        .collect();
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCH_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>StandardErrorPath</key>
    <string>{}</string>
</dict>
</plist>
"#,
        xml_escape(&log.to_string_lossy())
    );
    let path = launch_agent_plist()?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(&path, plist).with_context(|| format!("could not write {}", path.display()))?;
    let domain = format!("gui/{}", unsafe { libc::getuid() });
    // Replace a running copy (an older binary, or different settings).
    let _ = Command::new("launchctl")
        .args(["bootout", &domain])
        .arg(&path)
        .output();
    let out = Command::new("launchctl")
        .args(["bootstrap", &domain])
        .arg(&path)
        .output()
        .context("could not run launchctl")?;
    if !out.status.success() {
        bail!(
            "launchctl couldn't start the agent: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    eprintln!(
        "The stash SSH agent now starts at login ({}).",
        path.display()
    );
    eprintln!();
    eprintln!("To use it for SSH, add this to the top of ~/.ssh/config:");
    eprintln!();
    eprintln!("    Host *");
    eprintln!("        IdentityAgent \"{}\"", tilde(socket)?);
    eprintln!();
    eprintln!(
        "Or for one shell: export SSH_AUTH_SOCK=\"{}\"",
        socket.display()
    );
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let path = launch_agent_plist()?;
    if !path.exists() {
        eprintln!("The stash SSH agent isn't installed.");
        return Ok(());
    }
    let domain = format!("gui/{}", unsafe { libc::getuid() });
    let _ = Command::new("launchctl")
        .args(["bootout", &domain])
        .arg(&path)
        .output();
    fs::remove_file(&path)?;
    eprintln!(
        "Removed the stash SSH agent login item. Remember to remove IdentityAgent from ~/.ssh/config."
    );
    Ok(())
}

fn tilde(path: &Path) -> Result<String> {
    let home = home()?;
    Ok(match path.strip_prefix(&home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    })
}

/// Sign git commits and tags with an SSH key from the vault.
///
/// Git signs with `ssh-keygen -Y sign`, which takes the private key from an
/// agent when given only the public key. stash points git at a small
/// wrapper that runs `ssh-keygen` with the stash agent's socket, so nothing
/// else on the system has to change.
pub fn git_setup(vault: &Vault, name: &str, socket: &Path, global: bool) -> Result<()> {
    let pair = key_pair(vault, name)?;
    let stash_dir = vault
        .path()
        .parent()
        .context("the vault has no parent directory")?
        .to_owned();

    // The wrapper git runs instead of ssh-keygen.
    let wrapper = stash_dir.join("git-ssh-sign");
    let script = format!(
        "#!/bin/sh\n\
         # Written by `stash ssh git-setup`: signs with the stash SSH agent.\n\
         export SSH_AUTH_SOCK='{}'\n\
         if [ ! -S \"$SSH_AUTH_SOCK\" ]; then\n\
         \techo \"stash: the SSH agent isn't running; start it with 'stash ssh install' (or 'stash ssh agent')\" >&2\n\
         fi\n\
         exec ssh-keygen \"$@\"\n",
        socket.to_string_lossy().replace('\'', "'\\''")
    );
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o700)
        .open(&wrapper)
        .with_context(|| format!("could not write {}", wrapper.display()))?;
    file.write_all(script.as_bytes())?;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;

    let scope = if global { "--global" } else { "--local" };
    let git = |args: &[&str]| -> Result<String> {
        let out = Command::new("git")
            .arg("config")
            .args(args)
            .output()
            .context("could not run git")?;
        if !out.status.success() && !args.is_empty() && args[0] != "--get" {
            bail!(
                "git config {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    };

    let public = pair.public_line();
    // Without the comment: git compares this to allowed_signers entries.
    let bare = public
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let signing_key = format!("key::{bare}");
    let wrapper_str = wrapper.to_string_lossy().into_owned();
    for (key, value) in [
        ("gpg.format", "ssh"),
        ("user.signingkey", signing_key.as_str()),
        ("gpg.ssh.program", wrapper_str.as_str()),
        ("commit.gpgsign", "true"),
        ("tag.gpgsign", "true"),
    ] {
        git(&[scope, key, value])?;
    }

    // Let `git log --show-signature` verify your own signatures.
    let email = git(&["--get", "user.email"])?;
    if !email.is_empty() {
        let signers = stash_dir.join("allowed_signers");
        let entry = format!("{email} namespaces=\"git\" {bare}");
        let existing = fs::read_to_string(&signers).unwrap_or_default();
        if !existing.lines().any(|l| l.trim() == entry) {
            let mut f = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&signers)?;
            writeln!(f, "{entry}")?;
        }
        git(&[
            scope,
            "gpg.ssh.allowedSignersFile",
            &signers.to_string_lossy(),
        ])?;
    }

    let where_ = if global {
        "all your repositories"
    } else {
        "this repository"
    };
    eprintln!(
        "Git will now sign commits and tags in {where_} with {name} ({}).",
        pair.fingerprint()
    );
    eprintln!("Each signature asks for Touch ID. Make sure the agent runs: `stash ssh install`.");
    eprintln!();
    eprintln!(
        "For GitHub's \"Verified\" badge, add the key as a *signing* key (Settings → SSH and GPG keys → New SSH key → Key type: Signing Key):"
    );
    println!("{public}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("600").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("45s").unwrap(), Duration::from_secs(45));
        assert!(parse_duration("ten").is_err());
        assert!(parse_duration("5d").is_err());
    }
}
