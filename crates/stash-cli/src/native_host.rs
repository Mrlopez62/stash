//! `stash native-host`: the bridge between the stash browser extension and
//! the vault, over the browser's native messaging (a 4-byte length, then
//! JSON, on stdin and stdout).
//!
//! The browser starts it when the extension connects. The rules that keep
//! autofill safe are enforced here, not in the extension:
//!
//! - **Only a real browser can use it.** The process that started us must be
//!   a browser signed by its maker (checked through the code signature's
//!   Team ID on macOS), and the browser must name one of stash's extension
//!   IDs. Any other program running `stash native-host` is refused before
//!   it can ask for anything.
//! - **A login fills only where its website matches the page**
//!   (`stash_core::site`), checked again on every fill.
//! - **Every card or bank fill needs Touch ID**, on a prompt naming the card
//!   and the site, even while unlocked. Cards fill only on https pages.
//! - **Values only on demand.** Suggestions carry names, usernames, and card
//!   summaries ("Visa •••• 4242"). Secret values are sent only for the one
//!   item the user picked.
//! - **The key stays in this process's memory**, forgotten after
//!   `IDLE_LOCK` without use or when the browser disconnects.
//! - **Every fill is logged** in the audit log, by item name and site.
//!
//! Requests: `{"id": 1, "type": "status" | "suggest" | "unlock" | "fill" |
//! "lock", "url": "...", "name": "..."}`. Every reply echoes `id` and has
//! `ok`, plus either the result or `error`.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
use stash_core::item::{
    ACCOUNT_HOLDER, ACCOUNT_NUMBER, ACCOUNT_TYPE, BANK_NAME, BILLING_ZIP, CARD_NUMBER, CARDHOLDER,
    CVV, EXPIRY, IBAN, PASSWORD, ROUTING_NUMBER, SWIFT,
};
use stash_core::otp::Totp;
use stash_core::{FieldKind, Item, Kind, Vault, payment, site};
use zeroize::Zeroizing;

use crate::{audit, procinfo, text, touchid};

pub const HOST_NAME: &str = "dev.stash.autofill";
/// The unpacked Chrome extension's ID, fixed by the `key` in its manifest.
pub const CHROME_EXTENSION_ID: &str = "jddlnapigcddjhnbbjblfjdgfplocfef";
pub const FIREFOX_EXTENSION_ID: &str = "autofill@stash.dev";
const IDLE_LOCK: Duration = Duration::from_secs(10 * 60);
/// Native messaging allows 1 MB from the host; requests here are tiny.
const MAX_REQUEST: usize = 64 * 1024;

/// Code-signing Team IDs of the browsers that may start the host (macOS).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const BROWSER_TEAMS: &[(&str, &str)] = &[
    ("EQHXZ8M8AV", "Google Chrome"),
    ("43AQ936H96", "Firefox"),
    ("KL8N8XSYF4", "Brave"),
    ("UBF8T346G9", "Microsoft Edge"),
    ("S6N382Y83G", "Arc"),
];

/// Is this launch from one of stash's extensions? Chrome passes the
/// caller's origin first; Firefox passes the manifest path, then the ID.
/// (Anyone can type these arguments, so this is checked *in addition to*
/// the browser's identity, never instead of it.)
pub fn caller_is_allowed(args: &[String]) -> bool {
    let chrome = format!("chrome-extension://{CHROME_EXTENSION_ID}/");
    args.iter()
        .any(|a| *a == chrome || *a == FIREFOX_EXTENSION_ID)
}

/// The `.app` bundle an executable belongs to.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn app_bundle(exe: &Path) -> Option<PathBuf> {
    exe.ancestors()
        .find(|p| p.extension().is_some_and(|e| e == "app"))
        .map(Path::to_owned)
}

/// `TeamIdentifier=…` from `codesign -dv` output.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn team_id(codesign_output: &str) -> Option<&str> {
    codesign_output
        .lines()
        .find_map(|l| l.strip_prefix("TeamIdentifier="))
        .map(str::trim)
        .filter(|t| *t != "not set")
}

/// The browser that started us, by its verified code signature: its name,
/// or why it isn't one.
#[cfg(target_os = "macos")]
fn verified_browser(pid: i32) -> Result<String, String> {
    use std::process::Command;
    let exe = procinfo::exe_path(pid).ok_or("couldn't tell which program started stash")?;
    let bundle = app_bundle(&exe).ok_or_else(|| format!("{} isn't a browser", exe.display()))?;
    // A valid signature (nothing in the bundle's main code was changed)…
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(&bundle)
        .output()
        .map_err(|e| format!("couldn't run codesign: {e}"))?;
    if !verify.status.success() {
        return Err(format!("{} isn't validly signed", bundle.display()));
    }
    // …from a browser maker.
    let info = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=2"])
        .arg(&bundle)
        .output()
        .map_err(|e| format!("couldn't run codesign: {e}"))?;
    let details = String::from_utf8_lossy(&info.stderr);
    let team = team_id(&details).unwrap_or("none");
    BROWSER_TEAMS
        .iter()
        .find(|(t, _)| *t == team)
        .map(|(_, name)| (*name).to_owned())
        .ok_or_else(|| {
            format!(
                "{} (Team ID {team}) isn't a supported browser",
                bundle.display()
            )
        })
}

/// On Linux there are no code signatures to check; a browser installed by
/// the system (owned by root, not writable by you) is accepted.
#[cfg(not(target_os = "macos"))]
fn verified_browser(pid: i32) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    let exe = procinfo::exe_path(pid).ok_or("couldn't tell which program started stash")?;
    let meta = std::fs::metadata(&exe).map_err(|e| e.to_string())?;
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let known = ["chrome", "chromium", "firefox", "brave", "msedge"]
        .iter()
        .any(|b| name.contains(b));
    if meta.uid() == 0 && meta.mode() & 0o022 == 0 && known {
        Ok(name)
    } else {
        Err(format!(
            "{} isn't a system-installed browser",
            exe.display()
        ))
    }
}

/// The browser that started us. Chrome may start hosts from a helper
/// process, so the grandparent is checked too.
fn browser() -> Result<String, String> {
    let parent = std::os::unix::process::parent_id() as i32;
    match verified_browser(parent) {
        Ok(name) => Ok(name),
        Err(why) => procinfo::info(parent)
            .and_then(|p| verified_browser(p.ppid).ok())
            .ok_or(why),
    }
}

/// How the host unlocks and approves. Touch ID in real use.
pub trait Gate {
    fn unlock(&mut self, vault: &Path, reason: &str) -> Result<Vault, String>;
    fn approve(&mut self, reason: &str) -> Result<(), String>;
}

pub struct TouchIdGate;

fn describe(e: touchid::UnlockError) -> String {
    match e {
        touchid::UnlockError::Cancelled => "cancelled".into(),
        touchid::UnlockError::Unavailable(why) => format!("Touch ID unavailable: {why}"),
        touchid::UnlockError::Failed(why) => format!("Touch ID failed: {why}"),
    }
}

impl Gate for TouchIdGate {
    fn unlock(&mut self, vault: &Path, reason: &str) -> Result<Vault, String> {
        let helper = touchid::helper().ok_or("the stash-touchid helper was not found")?;
        if !touchid::is_enrolled(vault) {
            return Err("browser autofill needs Touch ID; run `stash touchid enable`".into());
        }
        let key = touchid::unlock(&helper, vault, reason).map_err(describe)?;
        Vault::open_with_key(vault, &key).map_err(|e| e.to_string())
    }

    fn approve(&mut self, reason: &str) -> Result<(), String> {
        let helper = touchid::helper().ok_or("the stash-touchid helper was not found")?;
        touchid::confirm(&helper, reason).map_err(describe)
    }
}

pub struct Host<G: Gate> {
    vault_path: PathBuf,
    audit_log: PathBuf,
    browser: String,
    gate: G,
    unlocked: Option<(Vault, Instant)>,
}

impl<G: Gate> Host<G> {
    pub fn new(vault_path: PathBuf, browser: String, gate: G) -> Self {
        Self {
            audit_log: audit::path_for(&vault_path),
            vault_path,
            browser,
            gate,
            unlocked: None,
        }
    }

    fn vault(&mut self) -> Option<&Vault> {
        if self
            .unlocked
            .as_ref()
            .is_some_and(|(_, at)| at.elapsed() >= IDLE_LOCK)
        {
            self.unlocked = None;
        }
        let (vault, at) = self.unlocked.as_mut()?;
        *at = Instant::now();
        Some(vault)
    }

    fn unlock(&mut self, reason: &str) -> Result<(), String> {
        let vault = self.gate.unlock(&self.vault_path, reason)?;
        self.unlocked = Some((vault, Instant::now()));
        Ok(())
    }

    pub fn respond(&mut self, request: &Value) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let result = match request.get("type").and_then(Value::as_str) {
            Some("status") => Ok(json!({
                "locked": self.vault().is_none(),
                "version": env!("CARGO_PKG_VERSION"),
            })),
            Some("suggest") => self.suggest(request),
            Some("unlock") => self.unlock_and_suggest(request),
            Some("fill") => self.fill(request),
            Some("lock") => {
                self.unlocked = None;
                Ok(json!({ "locked": true }))
            }
            _ => Err("unknown request".to_owned()),
        };
        match result {
            Ok(Value::Object(mut map)) => {
                map.insert("id".into(), id);
                map.insert("ok".into(), true.into());
                Value::Object(map)
            }
            Ok(_) => unreachable!("results are objects"),
            Err(error) => json!({ "id": id, "ok": false, "error": error }),
        }
    }

    fn page(request: &Value) -> Result<(String, String), String> {
        let url = request
            .get("url")
            .and_then(Value::as_str)
            .ok_or("missing url")?
            .to_owned();
        site::check_page(&url).map_err(|e| e.to_string())?;
        let host = site::display_host(&url).ok_or("missing host")?;
        Ok((url, text::clean(&host, 80)))
    }

    fn suggest(&mut self, request: &Value) -> Result<Value, String> {
        let (url, host) = Self::page(request)?;
        let Some(vault) = self.vault() else {
            return Ok(json!({ "locked": true, "host": host, "logins": [], "payments": [] }));
        };
        let mut logins = Vec::new();
        let mut payments = Vec::new();
        for summary in vault.summaries().map_err(|e| e.to_string())? {
            match summary.kind {
                Kind::Login => {
                    let item = vault.item(&summary.name).map_err(|e| e.to_string())?;
                    if matches_page(&item, &url) {
                        logins.push(json!({
                            "name": summary.name,
                            "username": item.username(),
                            "has_otp": item.fields.iter().any(|f| f.kind == FieldKind::Otp),
                        }));
                    }
                }
                Kind::Card | Kind::Bank => payments.push(json!({
                    "name": summary.name,
                    "kind": summary.kind,
                    "summary": summary.subtitle,
                })),
                _ => {}
            }
        }
        Ok(json!({ "locked": false, "host": host, "logins": logins, "payments": payments }))
    }

    fn unlock_and_suggest(&mut self, request: &Value) -> Result<Value, String> {
        let (_, host) = Self::page(request)?;
        if self.vault().is_none() {
            self.unlock(&format!(
                "unlock stash to fill logins and payments on {host} in {}",
                self.browser
            ))?;
        }
        self.suggest(request)
    }

    fn fill(&mut self, request: &Value) -> Result<Value, String> {
        let (url, host) = Self::page(request)?;
        let name = request
            .get("name")
            .and_then(Value::as_str)
            .ok_or("missing name")?
            .to_owned();
        let mut event = audit::Event {
            time: audit::now_rfc3339(),
            client: self.browser.clone(),
            tool: "autofill".into(),
            secrets: vec![name.clone()],
            command: None,
            outcome: "approved".into(),
            exit_code: None,
            detail: Some(format!("fill on {host}")),
        };
        // What the extension believes it's filling: decides, while locked,
        // whether a fill may unlock (payments ask anyway; logins don't).
        let wants_payment = matches!(
            request.get("kind").and_then(Value::as_str),
            Some("card" | "bank")
        );
        let result = self.fill_values(&url, &host, &name, wants_payment);
        if let Err(why) = &result {
            event.outcome = if why == "cancelled" {
                "denied"
            } else if why.starts_with("blocked:") {
                "blocked"
            } else {
                "error"
            }
            .into();
            event.detail = Some(format!("fill on {host}: {why}"));
        }
        if let Err(e) = audit::record(&self.audit_log, &event) {
            eprintln!("stash native-host: could not write the audit log: {e:#}");
        }
        result.map_err(|why| why.trim_start_matches("blocked: ").to_owned())
    }

    fn fill_values(
        &mut self,
        url: &str,
        host: &str,
        name: &str,
        wants_payment: bool,
    ) -> Result<Value, String> {
        // What kind of item it is decides the rule, so look before asking.
        let summary = match self.vault() {
            Some(vault) => Some(
                vault
                    .summaries()
                    .map_err(|e| e.to_string())?
                    .into_iter()
                    .find(|s| s.name == name)
                    .ok_or_else(|| format!("no item named {name}"))?,
            ),
            None => None,
        };
        match summary.as_ref().map(|s| s.kind) {
            None if wants_payment => self.unlock_and_fill_payment(host, name),
            None => Err("stash is locked".into()),
            Some(Kind::Login) => self.fill_login(url, name),
            Some(Kind::Card | Kind::Bank) => {
                let what = summary
                    .and_then(|s| s.subtitle)
                    .unwrap_or_else(|| name.to_owned());
                self.fill_payment(host, name, &what)
            }
            Some(_) => Err(format!("blocked: {name} can't be filled into web pages")),
        }
    }

    /// A payment fill while locked: its own Touch ID prompt, naming the
    /// payment and the site, unlocks too. (A login fill while locked just
    /// says so; the popup offers to unlock.)
    fn unlock_and_fill_payment(&mut self, host: &str, name: &str) -> Result<Value, String> {
        let reason = format!(
            "fill your payment details “{}” on {host} in {}",
            text::clean(name, 40),
            self.browser
        );
        self.unlock(&reason)?;
        let vault = self.vault().ok_or("stash is locked")?;
        let item = vault.item(name).map_err(|e| e.to_string())?;
        if !item.kind.is_payment() {
            return Err(format!("blocked: {name} isn't a card or bank account"));
        }
        Ok(payment_values(&item))
    }

    fn fill_login(&mut self, url: &str, name: &str) -> Result<Value, String> {
        let vault = self.vault().ok_or("stash is locked")?;
        let item = vault.item(name).map_err(|e| e.to_string())?;
        if !matches_page(&item, url) {
            return Err(format!("blocked: {name} isn't saved for this site"));
        }
        let password = item
            .labeled(PASSWORD)
            .or_else(|| item.fields.iter().find(|f| f.kind == FieldKind::Concealed))
            .map(|f| Zeroizing::new(f.value.clone()));
        let otp = match item.fields.iter().find(|f| f.kind == FieldKind::Otp) {
            Some(f) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                Some(
                    Totp::parse(&f.value)
                        .map_err(|e| e.to_string())?
                        .code_at(now),
                )
            }
            None => None,
        };
        Ok(json!({
            "kind": "login",
            "username": item.username(),
            "password": password.as_ref().map(|p| p.as_str()),
            "otp": otp,
        }))
    }

    /// Cards and bank accounts: a fingerprint every time, on a prompt that
    /// names what's filled and where.
    fn fill_payment(&mut self, host: &str, name: &str, what: &str) -> Result<Value, String> {
        let reason = format!(
            "fill {} on {host} in {}",
            text::clean(what, 48),
            self.browser
        );
        self.gate.approve(&reason)?;
        let vault = self.vault().ok_or("stash is locked")?;
        let item = vault.item(name).map_err(|e| e.to_string())?;
        Ok(payment_values(&item))
    }
}

/// A card's or bank account's fields, as the extension fills them.
fn payment_values(item: &Item) -> Value {
    let get = |label: &str| item.labeled(label).map(|f| f.value.clone());
    let mut out = Map::new();
    if item.kind == Kind::Card {
        out.insert("kind".into(), "card".into());
        out.insert("cardholder".into(), get(CARDHOLDER).into());
        out.insert("number".into(), get(CARD_NUMBER).into());
        if let Some((month, year)) = get(EXPIRY).and_then(|e| payment::parse_expiry(&e).ok()) {
            out.insert("exp_month".into(), format!("{month:02}").into());
            out.insert("exp_year".into(), year.to_string().into());
        }
        out.insert("cvv".into(), get(CVV).into());
        out.insert("postal_code".into(), get(BILLING_ZIP).into());
        out.insert(
            "brand".into(),
            get(CARD_NUMBER).map(|n| payment::brand(&n).name()).into(),
        );
    } else {
        out.insert("kind".into(), "bank".into());
        out.insert("bank".into(), get(BANK_NAME).into());
        out.insert("holder".into(), get(ACCOUNT_HOLDER).into());
        out.insert("account_type".into(), get(ACCOUNT_TYPE).into());
        out.insert("routing".into(), get(ROUTING_NUMBER).into());
        out.insert("account".into(), get(ACCOUNT_NUMBER).into());
        out.insert("iban".into(), get(IBAN).into());
        out.insert("swift".into(), get(SWIFT).into());
    }
    Value::Object(out)
}

fn matches_page(item: &Item, url: &str) -> bool {
    item.fields
        .iter()
        .filter(|f| f.kind == FieldKind::Url)
        .any(|f| site::may_fill(url, &f.value).unwrap_or(false))
}

fn read_message(input: &mut impl Read) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_REQUEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request too large",
        ));
    }
    let mut message = Zeroizing::new(vec![0u8; len]);
    input.read_exact(&mut message)?;
    Ok(Some(message))
}

fn write_message(output: &mut impl Write, value: &Value) -> io::Result<()> {
    let body = Zeroizing::new(serde_json::to_vec(value)?);
    output.write_all(&(body.len() as u32).to_ne_bytes())?;
    output.write_all(&body)?;
    output.flush()
}

/// Serve the extension until the browser disconnects.
pub fn serve(vault: &Path, args: &[String]) -> Result<()> {
    if !caller_is_allowed(args) {
        bail!("stash native-host only answers the stash browser extension");
    }
    // Debug builds skip the browser check so tests can drive the host.
    let browser = match browser() {
        Ok(name) => name,
        Err(_) if cfg!(debug_assertions) => "a test browser".to_owned(),
        Err(why) => bail!("stash native-host only serves a signed web browser: {why}"),
    };
    let mut host = Host::new(vault.to_owned(), browser, TouchIdGate);
    let stdin = io::stdin();
    let stdout = io::stdout();
    let (mut input, mut output) = (stdin.lock(), stdout.lock());
    while let Some(message) = read_message(&mut input)? {
        let reply = match serde_json::from_slice::<Value>(&message) {
            Ok(request) => host.respond(&request),
            Err(_) => json!({ "ok": false, "error": "invalid request" }),
        };
        write_message(&mut output, &reply)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stash_core::KdfParams;
    use stash_core::item::CardDetails;
    use std::cell::RefCell;
    use std::rc::Rc;
    use tempfile::TempDir;

    #[derive(Default)]
    struct Prompts {
        seen: Vec<String>,
        deny: bool,
    }

    struct TestGate(Rc<RefCell<Prompts>>);

    impl Gate for TestGate {
        fn unlock(&mut self, vault: &Path, reason: &str) -> Result<Vault, String> {
            let mut p = self.0.borrow_mut();
            p.seen.push(format!("unlock: {reason}"));
            if p.deny {
                return Err("cancelled".into());
            }
            Vault::open(vault, b"pw").map_err(|e| e.to_string())
        }
        fn approve(&mut self, reason: &str) -> Result<(), String> {
            let mut p = self.0.borrow_mut();
            p.seen.push(format!("approve: {reason}"));
            if p.deny {
                Err("cancelled".into())
            } else {
                Ok(())
            }
        }
    }

    fn host() -> (TempDir, Host<TestGate>, Rc<RefCell<Prompts>>) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.db");
        let fast = KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let mut vault = Vault::create(&path, b"pw", fast).unwrap();
        let mut github = Item::login(Some("octocat"), "hunter2!", Some("https://github.com"));
        github.set("one-time password", FieldKind::Otp, "JBSWY3DPEHPK3PXP");
        vault.put("github", &github, false).unwrap();
        vault
            .put(
                "gitlab",
                &Item::login(Some("me"), "pw2", Some("gitlab.com")),
                false,
            )
            .unwrap();
        vault.put("token", &Item::secret("ghp_x"), false).unwrap();
        let card = Item::card(&CardDetails {
            cardholder: Some("J Lopez"),
            number: "4242 4242 4242 4242",
            expiry: Some("08/27"),
            cvv: Some("123"),
            billing_zip: Some("78666"),
            ..Default::default()
        })
        .unwrap();
        vault.put("cards/visa", &card, false).unwrap();
        let prompts = Rc::new(RefCell::new(Prompts::default()));
        let host = Host::new(path, "Test Browser".into(), TestGate(Rc::clone(&prompts)));
        (dir, host, prompts)
    }

    fn unlocked() -> (TempDir, Host<TestGate>, Rc<RefCell<Prompts>>) {
        let (dir, mut host, prompts) = host();
        host.respond(&json!({ "id": 0, "type": "unlock", "url": "https://github.com/" }));
        prompts.borrow_mut().seen.clear();
        (dir, host, prompts)
    }

    #[test]
    fn only_trusts_stash_extensions_and_browser_signatures() {
        let chrome = format!("chrome-extension://{CHROME_EXTENSION_ID}/");
        assert!(caller_is_allowed(&[chrome]));
        assert!(caller_is_allowed(&[
            "/x/dev.stash.autofill.json".into(),
            FIREFOX_EXTENSION_ID.into()
        ]));
        assert!(!caller_is_allowed(&[
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/".into()
        ]));
        assert!(!caller_is_allowed(&[]));
        let out = "Executable=/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\nTeamIdentifier=EQHXZ8M8AV\n";
        assert_eq!(team_id(out), Some("EQHXZ8M8AV"));
        assert_eq!(team_id("TeamIdentifier=not set\n"), None);
        assert_eq!(
            app_bundle(Path::new(
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
            )),
            Some(PathBuf::from("/Applications/Google Chrome.app"))
        );
        assert_eq!(app_bundle(Path::new("/usr/bin/python3")), None);
    }

    #[test]
    fn this_test_runner_is_not_a_browser() {
        let me = std::process::id() as i32;
        assert!(verified_browser(me).is_err());
    }

    #[test]
    fn suggests_matching_logins_and_payment_summaries_only() {
        let (_dir, mut host, _) = unlocked();
        let r =
            host.respond(&json!({ "id": 7, "type": "suggest", "url": "https://github.com/login" }));
        assert_eq!(r["id"], 7);
        assert_eq!(r["host"], "github.com");
        let logins = r["logins"].as_array().unwrap();
        assert_eq!(logins.len(), 1);
        assert_eq!(logins[0]["username"], "octocat");
        assert_eq!(r["payments"][0]["summary"], "Visa •••• 4242 · 08/27");
        let text = r.to_string();
        assert!(!text.contains("hunter2") && !text.contains("4242424242424242"));
    }

    #[test]
    fn fills_logins_only_on_their_site() {
        let (dir, mut host, prompts) = unlocked();
        let r = host.respond(&json!({ "id": 1, "type": "fill", "url": "https://github.com/login", "name": "github" }));
        assert_eq!(r["password"], "hunter2!", "{r}");
        assert_eq!(r["otp"].as_str().unwrap().len(), 6);
        assert!(prompts.borrow().seen.is_empty(), "logins reuse the unlock");
        for url in [
            "https://github.com.evil.io/login",
            "https://gitlab.com/",
            "http://github.com/",
        ] {
            let r = host.respond(&json!({ "id": 1, "type": "fill", "url": url, "name": "github" }));
            assert_eq!(r["ok"], false, "{url}: {r}");
            assert!(r.get("password").is_none());
        }
        let r = host.respond(
            &json!({ "id": 1, "type": "fill", "url": "https://github.com/", "name": "token" }),
        );
        assert_eq!(r["ok"], false, "secrets aren't filled: {r}");
        let log = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(log.contains(r#""outcome":"blocked""#) && !log.contains("hunter2"));
    }

    #[test]
    fn every_payment_fill_asks_and_names_the_site() {
        let (dir, mut host, prompts) = unlocked();
        let fill = json!({ "id": 1, "type": "fill", "url": "https://shop.example/checkout", "name": "cards/visa" });
        let r = host.respond(&fill);
        assert_eq!(r["number"], "4242424242424242", "{r}");
        assert_eq!(
            (r["exp_month"].as_str(), r["exp_year"].as_str()),
            (Some("08"), Some("2027"))
        );
        assert_eq!(r["cvv"], "123");
        host.respond(&fill);
        assert_eq!(
            prompts.borrow().seen,
            vec![
                "approve: fill Visa •••• 4242 · 08/27 on shop.example in Test Browser".to_owned();
                2
            ]
        );
        prompts.borrow_mut().deny = true;
        let r = host.respond(&fill);
        assert_eq!(r["ok"], false);
        assert!(r.get("number").is_none());
        let log = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(log.contains(r#""outcome":"denied""#) && !log.contains("4242424242424242"));
        // Never on plain http.
        let r = host.respond(&json!({ "id": 1, "type": "fill", "url": "http://shop.example/", "name": "cards/visa" }));
        assert_eq!(r["ok"], false);
    }

    #[test]
    fn a_locked_payment_fill_unlocks_with_one_prompt_naming_it() {
        let (_dir, mut host, prompts) = host();
        let r = host.respond(&json!({ "id": 1, "type": "fill", "url": "https://shop.example/", "name": "cards/visa", "kind": "card" }));
        assert_eq!(r["cvv"], "123", "{r}");
        assert_eq!(
            prompts.borrow().seen,
            vec![
                "unlock: fill your payment details “cards/visa” on shop.example in Test Browser"
                    .to_owned()
            ]
        );
    }

    #[test]
    fn locked_logins_need_an_unlock_first() {
        let (_dir, mut host, prompts) = host();
        let r = host.respond(&json!({ "id": 2, "type": "suggest", "url": "https://github.com/" }));
        assert_eq!(r["locked"], true);
        let r = host.respond(&json!({ "id": 3, "type": "fill", "url": "https://github.com/", "name": "github", "kind": "login" }));
        assert_eq!(r["error"], "stash is locked");
        assert!(
            prompts.borrow().seen.is_empty(),
            "no prompt that would mislabel a login"
        );
        // Claiming a login is a card still can't get it filled.
        let r = host.respond(&json!({ "id": 4, "type": "fill", "url": "https://github.com/", "name": "github", "kind": "card" }));
        assert_eq!(r["ok"], false);
        assert!(r.get("password").is_none() && r.get("number").is_none());
    }

    #[test]
    fn frames_messages_like_browsers_do() {
        let mut buf = Vec::new();
        write_message(&mut buf, &json!({ "a": 1 })).unwrap();
        assert_eq!(
            u32::from_ne_bytes(buf[..4].try_into().unwrap()) as usize,
            buf.len() - 4
        );
        let mut input = &buf[..];
        let message = read_message(&mut input).unwrap().unwrap();
        assert_eq!(&message[..], br#"{"a":1}"#);
        assert!(read_message(&mut input).unwrap().is_none());
        let mut huge = ((MAX_REQUEST + 1) as u32).to_ne_bytes().to_vec();
        huge.extend_from_slice(b"{}");
        assert!(read_message(&mut &huge[..]).is_err());
    }
}
