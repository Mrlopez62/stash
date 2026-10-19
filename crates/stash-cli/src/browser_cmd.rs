//! `stash browser`: connect the stash browser extension to this vault.
//!
//! `install` does three things:
//! 1. writes a small launcher (`~/.stash/native-host`) that runs
//!    `stash native-host` for this vault,
//! 2. registers it with each installed browser (a native messaging host
//!    manifest that only stash's extension IDs may use),
//! 3. unpacks the extension (built into this binary) to
//!    `~/.stash/browser-extension`, ready for "Load unpacked".

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::json;

use crate::native_host::{CHROME_EXTENSION_ID, FIREFOX_EXTENSION_ID, HOST_NAME};

macro_rules! extension_files {
    ($($path:literal),* $(,)?) => {
        &[$(($path, include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../browser/extension/", $path)) as &[u8])),*]
    };
}

/// The extension, as shipped with this version of stash.
const EXTENSION: &[(&str, &[u8])] = extension_files![
    "manifest.json",
    "background.js",
    "fill.js",
    "popup.html",
    "popup.css",
    "popup.js",
    "icons/icon-16.png",
    "icons/icon-32.png",
    "icons/icon-48.png",
    "icons/icon-128.png",
    "fonts/IBMPlexSans.ttf",
    "fonts/JetBrainsMono.ttf",
    "fonts/OFL-IBMPlexSans.txt",
    "fonts/OFL-JetBrainsMono.txt",
];

#[derive(Clone, Copy, PartialEq)]
enum Family {
    Chromium,
    Firefox,
}

/// Browsers by name, family, and the directory that holds their profile
/// data (relative to the home directory).
fn browsers() -> Vec<(&'static str, Family, &'static str)> {
    if cfg!(target_os = "macos") {
        vec![
            (
                "Google Chrome",
                Family::Chromium,
                "Library/Application Support/Google/Chrome",
            ),
            (
                "Chrome Beta",
                Family::Chromium,
                "Library/Application Support/Google/Chrome Beta",
            ),
            (
                "Chromium",
                Family::Chromium,
                "Library/Application Support/Chromium",
            ),
            (
                "Brave",
                Family::Chromium,
                "Library/Application Support/BraveSoftware/Brave-Browser",
            ),
            (
                "Microsoft Edge",
                Family::Chromium,
                "Library/Application Support/Microsoft Edge",
            ),
            (
                "Arc",
                Family::Chromium,
                "Library/Application Support/Arc/User Data",
            ),
            (
                "Firefox",
                Family::Firefox,
                "Library/Application Support/Mozilla",
            ),
        ]
    } else {
        vec![
            ("Google Chrome", Family::Chromium, ".config/google-chrome"),
            ("Chromium", Family::Chromium, ".config/chromium"),
            (
                "Brave",
                Family::Chromium,
                ".config/BraveSoftware/Brave-Browser",
            ),
            ("Microsoft Edge", Family::Chromium, ".config/microsoft-edge"),
            ("Firefox", Family::Firefox, ".mozilla"),
        ]
    }
}

fn manifest_dir(profile: &Path, family: Family) -> PathBuf {
    match family {
        Family::Chromium => profile.join("NativeMessagingHosts"),
        Family::Firefox if cfg!(target_os = "macos") => profile.join("NativeMessagingHosts"),
        Family::Firefox => profile.join("native-messaging-hosts"),
    }
}

fn home() -> Result<PathBuf> {
    dirs::home_dir().context("could not find your home directory")
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn install(vault: &Path) -> Result<()> {
    if !vault.exists() {
        return Err(stash_core::Error::VaultMissing(vault.to_owned()).into());
    }
    let vault = vault.canonicalize()?;
    let stash_dir = vault
        .parent()
        .context("the vault has no parent directory")?;
    let exe = std::env::current_exe()?.canonicalize()?;

    // 1. The launcher. Browsers start a host with no arguments of our
    // choosing, so the vault comes from here.
    let launcher = stash_dir.join("native-host");
    let script = format!(
        "#!/bin/sh\n# Written by `stash browser install`: starts stash's browser bridge.\nexec {} --vault {} native-host \"$@\"\n",
        shell_quote(&exe.to_string_lossy()),
        shell_quote(&vault.to_string_lossy())
    );
    write_private(&launcher, script.as_bytes(), 0o700)?;

    // 2. Register with each browser that's installed.
    let home = home()?;
    let mut registered = Vec::new();
    for (name, family, profile) in browsers() {
        let profile = home.join(profile);
        if !profile.is_dir() {
            continue;
        }
        let dir = manifest_dir(&profile, family);
        fs::create_dir_all(&dir).with_context(|| format!("could not create {}", dir.display()))?;
        let mut manifest = json!({
            "name": HOST_NAME,
            "description": "stash browser autofill",
            "path": launcher,
            "type": "stdio",
        });
        if family == Family::Chromium {
            manifest["allowed_origins"] =
                json!([format!("chrome-extension://{CHROME_EXTENSION_ID}/")]);
        } else {
            manifest["allowed_extensions"] = json!([FIREFOX_EXTENSION_ID]);
        }
        let path = dir.join(format!("{HOST_NAME}.json"));
        write_private(
            &path,
            serde_json::to_string_pretty(&manifest)?.as_bytes(),
            0o644,
        )?;
        registered.push((name, family));
    }

    // 3. The extension itself.
    let extension = stash_dir.join("browser-extension");
    for (file, bytes) in EXTENSION {
        let path = extension.join(file);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, bytes).with_context(|| format!("could not write {}", path.display()))?;
    }

    if registered.is_empty() {
        eprintln!("No supported browser found (Chrome, Brave, Edge, Arc, Chromium, or Firefox).");
        return Ok(());
    }
    let names: Vec<&str> = registered.iter().map(|(n, _)| *n).collect();
    eprintln!("Connected stash to {}.", names.join(", "));
    eprintln!();
    if registered.iter().any(|(_, f)| *f == Family::Chromium) {
        eprintln!("Chrome, Brave, Edge, and Arc: load the extension once:");
        eprintln!(
            "  1. Open chrome://extensions (brave://, edge://, or arc:// for those browsers)"
        );
        eprintln!("  2. Turn on Developer mode, then click Load unpacked");
        eprintln!("  3. Choose {}", extension.display());
    }
    if registered.iter().any(|(_, f)| *f == Family::Firefox) {
        eprintln!(
            "Firefox: open about:debugging → This Firefox → Load Temporary Add-on, and choose"
        );
        eprintln!("  {}", extension.join("manifest.json").display());
        eprintln!("  (Firefox keeps unsigned add-ons only until it restarts.)");
    }
    eprintln!();
    eprintln!(
        "Then click the stash icon in the toolbar (or press ⌘⇧L) on a sign-in or checkout page."
    );
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("could not write {}", path.display()))?;
    file.write_all(bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let home = home()?;
    let mut removed = Vec::new();
    for (name, family, profile) in browsers() {
        let path = manifest_dir(&home.join(profile), family).join(format!("{HOST_NAME}.json"));
        if fs::remove_file(&path).is_ok() {
            removed.push(name);
        }
    }
    if removed.is_empty() {
        eprintln!("stash wasn't connected to any browser.");
    } else {
        eprintln!(
            "Disconnected stash from {}. Remove the extension in each browser's extensions page.",
            removed.join(", ")
        );
    }
    Ok(())
}

pub fn status() -> Result<()> {
    let home = home()?;
    let mut any = false;
    for (name, family, profile) in browsers() {
        let profile = home.join(profile);
        if !profile.is_dir() {
            continue;
        }
        any = true;
        let connected = manifest_dir(&profile, family)
            .join(format!("{HOST_NAME}.json"))
            .is_file();
        println!(
            "{name}: {}",
            if connected {
                "connected"
            } else {
                "not connected (run `stash browser install`)"
            }
        );
    }
    if !any {
        println!("No supported browser found.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ships_a_consistent_extension() {
        let manifest: serde_json::Value = serde_json::from_slice(
            EXTENSION
                .iter()
                .find(|(f, _)| *f == "manifest.json")
                .unwrap()
                .1,
        )
        .unwrap();
        assert_eq!(
            manifest["browser_specific_settings"]["gecko"]["id"],
            FIREFOX_EXTENSION_ID
        );
        assert_eq!(
            manifest["version"],
            env!("CARGO_PKG_VERSION"),
            "extension and stash versions match"
        );
        // The ID Chrome derives from the manifest key: first 16 bytes of its
        // SHA-256, as hex digits mapped 0-f → a-p.
        use base64::Engine;
        use sha2::Digest;
        let key = base64::engine::general_purpose::STANDARD
            .decode(manifest["key"].as_str().unwrap())
            .unwrap();
        let id: String = sha2::Sha256::digest(&key)[..16]
            .iter()
            .flat_map(|b| [b >> 4, b & 0xf])
            .map(|n| (b'a' + n) as char)
            .collect();
        assert_eq!(id, CHROME_EXTENSION_ID);
        // Least privilege: no access to sites beyond the active tab and the
        // payment processors' card frames.
        assert_eq!(
            manifest["permissions"],
            json!(["activeTab", "scripting", "nativeMessaging"])
        );
        assert_eq!(
            manifest["host_permissions"],
            json!([
                "https://js.stripe.com/*",
                "https://assets.braintreegateway.com/*"
            ])
        );
        assert!(manifest.get("content_scripts").is_none());
    }

    #[test]
    fn quotes_paths_for_the_launcher() {
        assert_eq!(shell_quote("/Users/a b/it's"), "'/Users/a b/it'\\''s'");
    }
}
