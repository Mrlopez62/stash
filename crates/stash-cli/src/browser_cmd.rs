//! `stash browser`: connect the stash browser extension to this vault.
//!
//! `install` does three things:
//! 1. writes a small launcher (`~/.stash/native-host`) that runs
//!    `stash native-host` for this vault,
//! 2. registers it with each installed browser (a native messaging host
//!    manifest that only stash's extension IDs may use),
//! 3. unpacks the extension (built into this binary) to
//!    `~/.stash/browser-extension/chrome` and `.../firefox`, each with a
//!    manifest for that browser, ready for "Load unpacked".

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{Value, json};

use crate::native_host::{CHROME_EXTENSION_ID, FIREFOX_EXTENSION_ID, HOST_NAME};

macro_rules! extension_files {
    ($($path:literal),* $(,)?) => {
        &[$(($path, include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../browser/extension/", $path)) as &[u8])),*]
    };
}

/// The extension, as shipped with this version of stash.
pub(crate) const EXTENSION: &[(&str, &[u8])] = extension_files![
    "manifest.json",
    "background.js",
    "fill.js",
    "popup.html",
    "popup.css",
    "popup.js",
    "menu.html",
    "inline.js",
    "save.html",
    "save.js",
    "options.html",
    "options.js",
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

impl Family {
    /// Where its copy of the extension is unpacked, under browser-extension/.
    fn folder(self) -> &'static str {
        match self {
            Family::Chromium => "chrome",
            Family::Firefox => "firefox",
        }
    }
}

/// The extension's manifest for one browser family. The shared manifest has
/// both browsers' keys (Chrome's service worker and fixed-ID `key`,
/// Firefox's background scripts and add-on ID); each browser warns about
/// the other's, so each copy gets only its own.
fn manifest_for(family: Family) -> Vec<u8> {
    let base = EXTENSION
        .iter()
        .find(|(f, _)| *f == "manifest.json")
        .expect("the extension has a manifest")
        .1;
    let mut manifest: Value = serde_json::from_slice(base).expect("the manifest is valid JSON");
    let top = manifest.as_object_mut().expect("the manifest is an object");
    let drop_background = match family {
        Family::Chromium => {
            top.remove("browser_specific_settings");
            "scripts"
        }
        Family::Firefox => {
            top.remove("key");
            top.remove("minimum_chrome_version");
            // Chrome-only: a per-session URL for the menu and save frames.
            if let Some(list) = top
                .get_mut("web_accessible_resources")
                .and_then(Value::as_array_mut)
            {
                for entry in list.iter_mut().filter_map(Value::as_object_mut) {
                    entry.remove("use_dynamic_url");
                }
            }
            "service_worker"
        }
    };
    if let Some(background) = top.get_mut("background").and_then(Value::as_object_mut) {
        background.remove(drop_background);
    }
    let mut bytes = serde_json::to_vec_pretty(&manifest).expect("JSON serializes");
    bytes.push(b'\n');
    bytes
}

/// Every file of the unpacked extensions, by path under browser-extension/.
fn unpacked_files() -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    for family in [Family::Chromium, Family::Firefox] {
        for (file, bytes) in EXTENSION {
            let bytes = if *file == "manifest.json" {
                manifest_for(family)
            } else {
                bytes.to_vec()
            };
            files.push((format!("{}/{file}", family.folder()), bytes));
        }
    }
    files
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

/// Why the unpacked extension next to the vault can't be trusted, if it
/// can't: a file that differs from the copy built into this binary, or one
/// that shouldn't be there. Chrome doesn't verify unpacked extensions, so
/// edited code there would run with stash's real ID.
pub(crate) fn tampered(extension: &Path) -> Option<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, PathBuf)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            // Browsers' and Finder's own bookkeeping.
            if name == "_metadata" || name == ".DS_Store" {
                continue;
            }
            if path.is_dir() {
                walk(&path, base, out);
            } else if let Ok(rel) = path.strip_prefix(base) {
                out.push((rel.to_string_lossy().into_owned(), path.clone()));
            }
        }
    }
    if !extension.is_dir() {
        return None;
    }
    let mut files = Vec::new();
    walk(extension, extension, &mut files);
    let shipped = unpacked_files();
    for (rel, path) in files {
        let expected = shipped.iter().find(|(f, _)| *f == rel).map(|(_, b)| b);
        let changed = match expected {
            None => true,
            Some(bytes) => fs::read(&path).map_or(true, |actual| actual != *bytes),
        };
        if changed {
            return Some(format!(
                "the stash extension's files were changed ({rel}). If you didn't do that, something on \
                 this Mac may be tampering with it. Run `stash browser install` to restore them, then \
                 reload the extension"
            ));
        }
    }
    None
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

    // 3. The extension itself, one copy per browser family. Start clean,
    // so files from an older version (or anything else) don't linger.
    let extension = stash_dir.join("browser-extension");
    if extension.exists() {
        fs::remove_dir_all(&extension)
            .with_context(|| format!("could not replace {}", extension.display()))?;
    }
    for (file, bytes) in unpacked_files() {
        let path = extension.join(&file);
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
        eprintln!("  3. Choose {}", extension.join("chrome").display());
        eprintln!("  (Already loaded from an older stash? Remove it, then load this folder.)");
    }
    if registered.iter().any(|(_, f)| *f == Family::Firefox) {
        eprintln!(
            "Firefox: open about:debugging → This Firefox → Load Temporary Add-on, and choose"
        );
        eprintln!("  {}", extension.join("firefox/manifest.json").display());
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
        // No content script runs anywhere unless the user turns on stash in
        // sign-in fields, which grants these, and only these, origins.
        assert!(manifest.get("content_scripts").is_none());
        assert_eq!(
            manifest["optional_host_permissions"],
            json!(["https://*/*", "http://localhost/*", "http://127.0.0.1/*"])
        );
    }

    #[test]
    fn notices_changed_or_added_extension_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let ext = dir.path().join("browser-extension");
        assert_eq!(tampered(&ext), None, "not unpacked: nothing to check");
        for (file, bytes) in unpacked_files() {
            let path = ext.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        fs::create_dir_all(ext.join("chrome/_metadata")).unwrap();
        fs::write(ext.join("chrome/_metadata/x"), "browser data").unwrap();
        assert_eq!(tampered(&ext), None);
        fs::write(ext.join("firefox/background.js"), "steal()").unwrap();
        assert!(tampered(&ext).unwrap().contains("firefox/background.js"));
        fs::write(ext.join("firefox/background.js"), EXTENSION[1].1).unwrap();
        fs::write(ext.join("chrome/extra.js"), "steal()").unwrap();
        assert!(tampered(&ext).unwrap().contains("chrome/extra.js"));
        fs::remove_file(ext.join("chrome/extra.js")).unwrap();
        // A copy of the old single-folder layout isn't stash's either.
        fs::write(ext.join("manifest.json"), "{}").unwrap();
        assert!(tampered(&ext).is_some());
    }

    #[test]
    fn each_browser_gets_a_manifest_without_the_others_keys() {
        let chrome: Value = serde_json::from_slice(&manifest_for(Family::Chromium)).unwrap();
        assert!(chrome.get("browser_specific_settings").is_none());
        assert!(chrome["background"].get("scripts").is_none());
        assert_eq!(chrome["background"]["service_worker"], "background.js");
        assert!(
            chrome.get("key").is_some(),
            "Chrome keeps the key that fixes its ID"
        );
        let firefox: Value = serde_json::from_slice(&manifest_for(Family::Firefox)).unwrap();
        assert!(firefox.get("key").is_none() && firefox.get("minimum_chrome_version").is_none());
        assert!(firefox["background"].get("service_worker").is_none());
        assert_eq!(firefox["background"]["scripts"], json!(["background.js"]));
        assert_eq!(
            firefox["browser_specific_settings"]["gecko"]["id"],
            FIREFOX_EXTENSION_ID
        );
        // Everything else is the same in both.
        assert_eq!(chrome["permissions"], firefox["permissions"]);
        assert_eq!(chrome["host_permissions"], firefox["host_permissions"]);
    }

    #[test]
    fn quotes_paths_for_the_launcher() {
        assert_eq!(shell_quote("/Users/a b/it's"), "'/Users/a b/it'\\''s'");
    }
}
