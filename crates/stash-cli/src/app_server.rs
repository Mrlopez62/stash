//! `stash app-server`: the backend of the stash Mac app.
//!
//! The app launches this as a child process and speaks JSON-RPC 2.0 to it
//! over stdin/stdout, one message per line. All vault logic stays here in
//! Rust; the app is only UI.
//!
//! Security model:
//! - **Only the app can talk to it.** There's no socket: the pipes belong
//!   to the parent that started it.
//! - **The key stays here.** It's held in this process's memory, never sent
//!   to the app or to the session agent, and dropped on `lock` or after the
//!   idle timeout.
//! - **Values only on demand.** `list` and `item` never include passwords,
//!   2FA secrets, or notes. The app asks for one value at a time (`reveal`,
//!   `otp`) when you click to show or copy it.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use stash_core::generate::{self, Rules};
use stash_core::item::FieldValue;
use stash_core::otp::Totp;
use stash_core::{Error, Field, FieldKind, Item, KdfParams, Kind, Vault};
use zeroize::Zeroizing;

use crate::touchid;

/// JSON-RPC error codes, so the app can react (e.g. show the lock screen).
mod code {
    pub const INVALID_PARAMS: i64 = -32602;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const PARSE: i64 = -32700;
    pub const FAILED: i64 = -32000;
    pub const LOCKED: i64 = -32001;
    pub const NOT_FOUND: i64 = -32002;
    pub const WRONG_PASSWORD: i64 = -32003;
    pub const CANCELLED: i64 = -32004;
    pub const NEEDS_UPGRADE: i64 = -32005;
    pub const ALREADY_EXISTS: i64 = -32006;
}

struct Failure {
    code: i64,
    message: String,
}

impl Failure {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn params(message: impl Into<String>) -> Self {
        Self::new(code::INVALID_PARAMS, message)
    }
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        let code = match &e {
            Error::NotFound(_) | Error::NoSuchField(..) => code::NOT_FOUND,
            Error::WrongPassword => code::WRONG_PASSWORD,
            Error::NeedsUpgrade | Error::UpgradeBlocked => code::NEEDS_UPGRADE,
            Error::AlreadyExists(_) => code::ALREADY_EXISTS,
            _ => code::FAILED,
        };
        Failure::new(code, e.to_string())
    }
}

impl From<anyhow::Error> for Failure {
    fn from(e: anyhow::Error) -> Self {
        Failure::new(code::FAILED, format!("{e:#}"))
    }
}

type Reply = std::result::Result<Value, Failure>;

pub fn serve(vault_path: PathBuf, idle_timeout: Duration) -> Result<()> {
    let mut server = Server {
        vault_path,
        idle_timeout,
        unlocked: None,
    };
    let stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    for line in stdin.lines() {
        let line = Zeroizing::new(line?);
        if line.trim().is_empty() {
            continue;
        }
        if let Some(response) = server.handle_line(&line) {
            let mut bytes = Zeroizing::new(serde_json::to_vec(&response)?);
            bytes.push(b'\n');
            stdout.write_all(&bytes)?;
            stdout.flush()?;
        }
    }
    Ok(())
}

struct Unlocked {
    vault: Vault,
    last_used: Instant,
}

struct Server {
    vault_path: PathBuf,
    idle_timeout: Duration,
    unlocked: Option<Unlocked>,
}

impl Server {
    fn handle_line(&mut self, line: &str) -> Option<Value> {
        let message: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return Some(error(
                    Value::Null,
                    code::PARSE,
                    &format!("parse error: {e}"),
                ));
            }
        };
        let id = message.get("id").cloned()?;
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let params = message.get("params").cloned().unwrap_or(json!({}));
        let reply = match method {
            "status" => Ok(self.status()),
            "create_vault" => self.create_vault(&params),
            "unlock" => self.unlock(&params),
            "lock" => {
                self.unlocked = None;
                Ok(json!({}))
            }
            "list" => self.list(),
            "item" => self.item(&params),
            "reveal" => self.reveal(&params),
            "otp" => self.otp(&params),
            "otp_uri" => self.otp_uri(&params),
            "save" => self.save(&params),
            "delete" => self.delete(&params),
            "generate" => generate_password(&params),
            "enable_touch_id" => self.enable_touch_id(&params),
            _ => Err(Failure::new(
                code::METHOD_NOT_FOUND,
                format!("unknown method `{method}`"),
            )),
        };
        Some(match reply {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(f) => error(id, f.code, &f.message),
        })
    }

    fn is_unlocked(&self) -> bool {
        self.unlocked
            .as_ref()
            .is_some_and(|u| u.last_used.elapsed() < self.idle_timeout)
    }

    /// The unlocked vault, refreshing the idle timer, or `LOCKED`.
    fn vault(&mut self) -> std::result::Result<&mut Vault, Failure> {
        if !self.is_unlocked() {
            self.unlocked = None;
            return Err(Failure::new(code::LOCKED, "stash is locked"));
        }
        let unlocked = self.unlocked.as_mut().expect("checked above");
        unlocked.last_used = Instant::now();
        Ok(&mut unlocked.vault)
    }

    fn status(&mut self) -> Value {
        if !self.is_unlocked() {
            self.unlocked = None;
        }
        let helper = touchid::helper();
        let touch_id_available = helper
            .as_deref()
            .is_some_and(|h| touchid::availability(h).is_ok());
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "vault_path": self.vault_path.display().to_string(),
            "vault_exists": self.vault_path.exists(),
            "locked": self.unlocked.is_none(),
            "touch_id_available": touch_id_available,
            "touch_id_enabled": touchid::is_enrolled(&self.vault_path),
            "needs_upgrade": self.unlocked.as_ref().is_some_and(|u| !u.vault.is_current()),
            "idle_timeout_seconds": self.idle_timeout.as_secs(),
        })
    }

    fn create_vault(&mut self, params: &Value) -> Reply {
        let password = password_param(params)?;
        if password.chars().count() < crate::MIN_PASSWORD_LEN {
            return Err(Failure::params(format!(
                "the master password must be at least {} characters",
                crate::MIN_PASSWORD_LEN
            )));
        }
        let vault = Vault::create(&self.vault_path, password.as_bytes(), KdfParams::default())?;
        self.unlocked = Some(Unlocked {
            vault,
            last_used: Instant::now(),
        });
        Ok(json!({}))
    }

    fn unlock(&mut self, params: &Value) -> Reply {
        let method = params
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("password");
        let vault = match method {
            "password" => {
                let password = password_param(params)?;
                Vault::open(&self.vault_path, password.as_bytes())?
            }
            "touch_id" => {
                let helper = touchid::helper()
                    .ok_or_else(|| Failure::new(code::FAILED, "the Touch ID helper is missing"))?;
                if !touchid::is_enrolled(&self.vault_path) {
                    return Err(Failure::new(
                        code::FAILED,
                        "Touch ID unlock isn't turned on",
                    ));
                }
                let key = touchid::unlock(&helper, &self.vault_path, "unlock stash").map_err(
                    |e| match e {
                        touchid::UnlockError::Cancelled => {
                            Failure::new(code::CANCELLED, "Touch ID was cancelled")
                        }
                        touchid::UnlockError::Unavailable(why)
                        | touchid::UnlockError::Failed(why) => Failure::new(code::FAILED, why),
                    },
                )?;
                Vault::open_with_key(&self.vault_path, &key)?
            }
            other => return Err(Failure::params(format!("unknown unlock method `{other}`"))),
        };
        self.unlocked = Some(Unlocked {
            vault,
            last_used: Instant::now(),
        });
        Ok(json!({}))
    }

    fn enable_touch_id(&mut self, params: &Value) -> Reply {
        // Like `stash touchid enable`: a new way in needs the master password.
        let password = password_param(params)?;
        let helper = touchid::helper()
            .ok_or_else(|| Failure::new(code::FAILED, "the Touch ID helper is missing"))?;
        let vault = Vault::open(&self.vault_path, password.as_bytes())?;
        touchid::enroll(&helper, &self.vault_path, vault.key())?;
        Ok(json!({}))
    }

    fn list(&mut self) -> Reply {
        let summaries = self.vault()?.summaries()?;
        let items: Vec<Value> = summaries
            .into_iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "kind": s.kind,
                    "username": s.username,
                    "url": s.url,
                    "has_otp": s.has_otp,
                    "updated": s.updated,
                })
            })
            .collect();
        Ok(json!({ "items": items }))
    }

    /// An item's shape, with every sensitive value left out.
    fn item(&mut self, params: &Value) -> Reply {
        let name = name_param(params, "name")?;
        let vault = self.vault()?;
        let (item, binary) = match vault.item(&name) {
            Ok(item) => (item, false),
            // Binary secrets can't be shown, but they can still be listed.
            Err(Error::NotText(_)) => (Item::secret(""), true),
            Err(e) => return Err(e.into()),
        };
        let fields: Vec<Value> = item
            .fields
            .iter()
            .map(|f| {
                let mut field = json!({ "label": f.label, "kind": f.kind });
                if !f.kind.is_sensitive() {
                    field["value"] = json!(f.value);
                }
                field
            })
            .collect();
        Ok(json!({
            "name": name,
            "kind": item.kind,
            "fields": fields,
            "has_notes": !item.notes.is_empty(),
            "binary": binary,
            "created": item.created,
            "updated": item.updated,
        }))
    }

    /// One value, on demand: a field by label, or `notes`.
    fn reveal(&mut self, params: &Value) -> Reply {
        let name = name_param(params, "name")?;
        let field = string_param(params, "field")?;
        let item = self.vault()?.item(&name)?;
        let value = if field == "notes" {
            Zeroizing::new(item.notes.clone())
        } else {
            let found = item
                .labeled(&field)
                .ok_or_else(|| Error::NoSuchField(name.clone(), field.clone()))?;
            if found.kind == FieldKind::Otp {
                return Err(Failure::params("use `otp` for 2FA codes"));
            }
            Zeroizing::new(found.value.clone())
        };
        Ok(json!({ "value": value.as_str() }))
    }

    fn otp(&mut self, params: &Value) -> Reply {
        let name = name_param(params, "name")?;
        let item = self.vault()?.item(&name)?;
        let secret = match item.kind {
            Kind::Secret => item.primary().unwrap_or("").to_owned(),
            _ => match item.field("otp") {
                Some(FieldValue::Otp(s)) => s.to_owned(),
                _ => return Err(Error::NoSuchField(name, "otp".into()).into()),
            },
        };
        let secret = Zeroizing::new(secret);
        let totp = Totp::parse(&secret)?;
        let now = crate::unix_now();
        Ok(json!({
            "code": totp.code_at(now),
            "remaining": totp.remaining(now),
            "period": totp.period,
        }))
    }

    /// An `otpauth://` link for adding this item's 2FA to an authenticator
    /// app (the app shows it as a QR code, never as text). It contains the
    /// 2FA secret, so the app asks for it only when you click to show it.
    fn otp_uri(&mut self, params: &Value) -> Reply {
        let name = name_param(params, "name")?;
        let item = self.vault()?.item(&name)?;
        let secret = Zeroizing::new(match item.kind {
            Kind::Secret => item.primary().unwrap_or("").to_owned(),
            _ => match item.field("otp") {
                Some(FieldValue::Otp(s)) => s.to_owned(),
                _ => return Err(Error::NoSuchField(name, "otp".into()).into()),
            },
        });
        let totp = Totp::parse(&secret)?;
        let title = name.rsplit('/').next().unwrap_or(&name).to_owned();
        let issuer = totp.issuer.clone().unwrap_or(title);
        let account = item
            .username()
            .map(str::to_owned)
            .unwrap_or_else(|| name.clone());
        let uri = totp.to_uri(&issuer, &account);
        Ok(json!({ "uri": uri.as_str(), "issuer": issuer, "account": account }))
    }

    /// Create or update an item. Fields sent without a `value` keep their
    /// stored value, so the app can edit an item without ever loading its
    /// secrets. `notes: null` keeps the stored notes.
    fn save(&mut self, params: &Value) -> Reply {
        let request: SaveRequest = serde_json::from_value(params.clone())
            .map_err(|e| Failure::params(format!("invalid item: {e}")))?;
        let vault = self.vault()?;
        let existing = match &request.original_name {
            Some(original) => Some(vault.item(original)?),
            None => None,
        };
        let renamed = request
            .original_name
            .as_deref()
            .is_some_and(|o| o != request.name);
        if (existing.is_none() || renamed) && vault.contains(&request.name)? {
            return Err(Error::AlreadyExists(request.name.clone()).into());
        }

        let mut fields = Vec::with_capacity(request.fields.len());
        for f in &request.fields {
            let value = match &f.value {
                Some(v) => {
                    if f.kind == FieldKind::Otp {
                        Totp::parse_new(v)
                            .map_err(|e| Failure::params(format!("{}: {e}", f.label)))?;
                    }
                    Zeroizing::new(v.clone())
                }
                None => {
                    let kept = existing
                        .as_ref()
                        .and_then(|item| item.fields.iter().find(|old| old.label == f.label));
                    match kept {
                        Some(old) => Zeroizing::new(old.value.clone()),
                        None => {
                            return Err(Failure::params(format!(
                                "`{}` has no stored value to keep",
                                f.label
                            )));
                        }
                    }
                }
            };
            fields.push(Field::new(&f.label, f.kind, value.as_str()));
        }
        if request.kind == Kind::Secret && fields.first().is_none_or(|f| f.value.is_empty()) {
            return Err(Failure::params("a secret needs a value"));
        }
        let notes = match (&request.notes, &existing) {
            (Some(n), _) => n.clone(),
            (None, Some(item)) => item.notes.clone(),
            (None, None) => String::new(),
        };
        let mut item = Item {
            kind: request.kind,
            fields,
            notes,
            created: existing.as_ref().map_or(0, |i| i.created),
            updated: 0,
        };
        vault.put(&request.name, &item, true)?;
        if renamed {
            vault.remove(request.original_name.as_deref().expect("renamed"))?;
        }
        item.notes.clear();
        Ok(json!({}))
    }

    fn delete(&mut self, params: &Value) -> Reply {
        let name = name_param(params, "name")?;
        self.vault()?.remove(&name)?;
        Ok(json!({}))
    }
}

#[derive(Deserialize)]
struct SaveField {
    label: String,
    kind: FieldKind,
    #[serde(default)]
    value: Option<String>,
}

impl Drop for SaveField {
    fn drop(&mut self) {
        if let Some(v) = &mut self.value {
            zeroize::Zeroize::zeroize(v);
        }
    }
}

#[derive(Deserialize)]
struct SaveRequest {
    name: String,
    #[serde(default)]
    original_name: Option<String>,
    kind: Kind,
    #[serde(default)]
    fields: Vec<SaveField>,
    #[serde(default)]
    notes: Option<String>,
}

impl Drop for SaveRequest {
    fn drop(&mut self) {
        if let Some(n) = &mut self.notes {
            zeroize::Zeroize::zeroize(n);
        }
    }
}

fn generate_password(params: &Value) -> Reply {
    let flag = |key: &str| params.get(key).and_then(Value::as_bool).unwrap_or(true);
    let rules = Rules {
        length: params
            .get("length")
            .and_then(Value::as_u64)
            .map_or(Rules::default().length, |n| n as usize),
        uppercase: flag("uppercase"),
        digits: flag("digits"),
        symbols: flag("symbols"),
    };
    let password = generate::password(rules)?;
    Ok(json!({ "password": password.as_str() }))
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn string_param(params: &Value, key: &str) -> std::result::Result<String, Failure> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Failure::params(format!("missing `{key}`")))
}

fn name_param(params: &Value, key: &str) -> std::result::Result<String, Failure> {
    let name = string_param(params, key)?;
    stash_core::validate_name(&name)?;
    Ok(name)
}

fn password_param(params: &Value) -> std::result::Result<Zeroizing<String>, Failure> {
    let password = Zeroizing::new(string_param(params, "password")?);
    if password.is_empty() {
        return Err(Failure::params("the password is empty"));
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    struct Fixture {
        _dir: TempDir,
        server: Server,
        next_id: u64,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let server = Server {
                vault_path: dir.path().join("vault.db"),
                idle_timeout: Duration::from_secs(60),
                unlocked: None,
            };
            let mut f = Self {
                _dir: dir,
                server,
                next_id: 0,
            };
            f.ok("create_vault", json!({ "password": "correct horse" }));
            f
        }

        fn call(&mut self, method: &str, params: Value) -> Value {
            self.next_id += 1;
            let line =
                json!({ "jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params });
            self.server.handle_line(&line.to_string()).unwrap()
        }

        fn ok(&mut self, method: &str, params: Value) -> Value {
            let r = self.call(method, params);
            assert!(r.get("error").is_none(), "{method}: {r}");
            r["result"].clone()
        }

        fn err(&mut self, method: &str, params: Value) -> (i64, String) {
            let r = self.call(method, params);
            let e = &r["error"];
            (
                e["code"].as_i64().unwrap(),
                e["message"].as_str().unwrap().to_owned(),
            )
        }

        fn github(&mut self) {
            self.ok(
                "save",
                json!({
                    "name": "github",
                    "kind": "login",
                    "fields": [
                        { "label": "username", "kind": "text", "value": "octocat" },
                        { "label": "password", "kind": "concealed", "value": "hunter2!" },
                        { "label": "website", "kind": "url", "value": "https://github.com" },
                        { "label": "one-time password", "kind": "otp", "value": "JBSWY3DPEHPK3PXP" },
                    ],
                    "notes": "recovery codes in the safe",
                }),
            );
        }
    }

    #[test]
    fn lists_and_shows_items_without_secret_values() {
        let mut f = Fixture::new();
        f.github();
        let list = f.ok("list", json!({}));
        assert_eq!(list["items"][0]["name"], "github");
        assert_eq!(list["items"][0]["username"], "octocat");
        assert_eq!(list["items"][0]["has_otp"], true);

        let item = f.ok("item", json!({ "name": "github" }));
        let shown = item.to_string();
        assert!(shown.contains("octocat") && shown.contains("https://github.com"));
        for secret in ["hunter2!", "JBSWY3DP", "recovery codes"] {
            assert!(!shown.contains(secret), "{secret} leaked: {shown}");
        }
        assert_eq!(item["has_notes"], true);
    }

    #[test]
    fn reveals_one_value_at_a_time() {
        let mut f = Fixture::new();
        f.github();
        let pw = f.ok("reveal", json!({ "name": "github", "field": "password" }));
        assert_eq!(pw["value"], "hunter2!");
        let notes = f.ok("reveal", json!({ "name": "github", "field": "notes" }));
        assert_eq!(notes["value"], "recovery codes in the safe");
        let code = f.ok("otp", json!({ "name": "github" }));
        assert_eq!(code["code"].as_str().unwrap().len(), 6);
        assert!(code["remaining"].as_u64().unwrap() <= 30);
        // 2FA secrets themselves are never revealed.
        let (c, _) = f.err(
            "reveal",
            json!({ "name": "github", "field": "one-time password" }),
        );
        assert_eq!(c, code::INVALID_PARAMS);
        // But they can be exported as an authenticator link (shown as a QR).
        let link = f.ok("otp_uri", json!({ "name": "github" }));
        assert_eq!(link["issuer"], "github");
        assert_eq!(link["account"], "octocat");
        let uri = link["uri"].as_str().unwrap();
        assert!(
            uri.starts_with("otpauth://totp/github:octocat?secret=JBSWY3DPEHPK3PXP"),
            "{uri}"
        );
        let code = |s: &str| stash_core::otp::Totp::parse(s).unwrap().code_at(0);
        assert_eq!(code(uri), code("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn edits_keep_values_the_app_never_loaded() {
        let mut f = Fixture::new();
        f.github();
        f.ok(
            "save",
            json!({
                "name": "github",
                "original_name": "github",
                "kind": "login",
                "fields": [
                    { "label": "username", "kind": "text", "value": "hubot" },
                    { "label": "password", "kind": "concealed" },
                    { "label": "one-time password", "kind": "otp" },
                ],
            }),
        );
        assert_eq!(
            f.ok("reveal", json!({ "name": "github", "field": "password" }))["value"],
            "hunter2!"
        );
        assert_eq!(
            f.ok("reveal", json!({ "name": "github", "field": "notes" }))["value"],
            "recovery codes in the safe"
        );
        let item = f.ok("item", json!({ "name": "github" }));
        assert_eq!(
            item["fields"].as_array().unwrap().len(),
            3,
            "website was removed"
        );
        assert_eq!(item["fields"][0]["value"], "hubot");
    }

    #[test]
    fn renames_and_refuses_clobbering() {
        let mut f = Fixture::new();
        f.github();
        f.ok("save", json!({ "name": "other", "kind": "secret", "fields": [{ "label": "value", "kind": "concealed", "value": "x" }] }));
        let (c, _) = f.err(
            "save",
            json!({ "name": "other", "original_name": "github", "kind": "login", "fields": [] }),
        );
        assert_eq!(c, code::ALREADY_EXISTS);
        f.ok(
            "save",
            json!({ "name": "work/github", "original_name": "github", "kind": "login",
                    "fields": [{ "label": "password", "kind": "concealed" }] }),
        );
        let names: Vec<String> = f.ok("list", json!({}))["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(names, ["other", "work/github"]);
        assert_eq!(
            f.ok(
                "reveal",
                json!({ "name": "work/github", "field": "password" })
            )["value"],
            "hunter2!"
        );
        let (c, _) = f.err(
            "save",
            json!({ "name": "new", "kind": "login",
            "fields": [{ "label": "password", "kind": "concealed" }] }),
        );
        assert_eq!(c, code::INVALID_PARAMS, "nothing to keep on a new item");
    }

    #[test]
    fn locks_explicitly_and_when_idle() {
        let mut f = Fixture::new();
        f.github();
        f.ok("lock", json!({}));
        assert_eq!(f.err("list", json!({})).0, code::LOCKED);
        assert_eq!(f.ok("status", json!({}))["locked"], true);

        assert_eq!(
            f.err("unlock", json!({ "password": "wrong" })).0,
            code::WRONG_PASSWORD
        );
        f.ok("unlock", json!({ "password": "correct horse" }));
        f.ok("list", json!({}));

        f.server.idle_timeout = Duration::ZERO;
        assert_eq!(f.err("list", json!({})).0, code::LOCKED);
        assert!(f.server.unlocked.is_none(), "the key is dropped when idle");
    }

    #[test]
    fn validates_input() {
        let mut f = Fixture::new();
        let (c, m) = f.err(
            "save",
            json!({ "name": "x", "kind": "login",
            "fields": [{ "label": "one-time password", "kind": "otp", "value": "short" }] }),
        );
        assert_eq!(c, code::INVALID_PARAMS, "{m}");
        let (c, _) = f.err(
            "save",
            json!({ "name": "../x", "kind": "note", "notes": "hi" }),
        );
        assert_eq!(c, code::FAILED);
        let (c, _) = f.err(
            "save",
            json!({ "name": "x", "kind": "secret", "fields": [] }),
        );
        assert_eq!(c, code::INVALID_PARAMS);
        assert_eq!(f.err("nope", json!({})).0, code::METHOD_NOT_FOUND);
        let g = f.ok("generate", json!({ "length": 30, "symbols": false }));
        assert_eq!(g["password"].as_str().unwrap().len(), 30);
    }
}
