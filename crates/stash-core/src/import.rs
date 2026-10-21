//! Reading other password managers' exports: Chrome, Brave, Edge, and Arc
//! (CSV), Safari and Apple Passwords (CSV), Firefox (CSV), Bitwarden (JSON
//! and CSV), 1Password (`.1pux`), and other CSVs with the usual column names
//! (LastPass, Proton Pass, Dashlane).
//!
//! [`read`] turns a file into stash items with suggested names; it never
//! touches a vault. Anything it can't turn into a valid item (a card number
//! that fails its checksum, say) is listed in [`Import::skipped`] with the
//! reason, never dropped silently.
//!
//! Exports hold every password in plain text. Callers keep the file's bytes
//! in `Zeroizing` memory; the parsed strings here are wiped when the items
//! are dropped, but JSON parsing makes copies that can't all be.

use std::collections::{BTreeMap, HashMap};
use std::io::{Cursor, Read};

use serde_json::Value;
use zeroize::Zeroizing;

use crate::item::{BankDetails, CardDetails, FieldKind, Item, Kind};
use crate::{Error, otp, site};

const OTP_LABEL: &str = "one-time password";

/// What a file held.
#[derive(Debug, Default)]
pub struct Import {
    /// Where it came from, for display: "Chrome", "1Password", ...
    pub format: String,
    pub entries: Vec<Entry>,
    pub skipped: Vec<Skipped>,
}

/// One item to import.
#[derive(Debug)]
pub struct Entry {
    /// Its name in the other app.
    pub title: String,
    /// A valid stash name for it (it may still clash with an existing item).
    pub name: String,
    pub item: Item,
    /// Parts that couldn't come along, like a 2FA secret that isn't valid.
    pub warnings: Vec<String>,
}

/// Something in the file that won't be imported, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub title: String,
    pub why: String,
}

/// Read an export file (its whole contents).
pub fn read(bytes: &[u8]) -> Result<Import, Error> {
    if bytes.starts_with(b"PK\x03\x04") {
        return one_password(bytes);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| invalid("the file isn't text (UTF-8), a .1pux, or a JSON export"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if text.trim_start().starts_with('{') {
        return bitwarden(text);
    }
    csv_export(text)
}

fn invalid(why: &str) -> Error {
    Error::Import(why.to_owned())
}

// ---- Names ----

/// "GitHub (work)" → "github-work": what stash names allow.
fn slug(text: &str) -> String {
    let mut out = String::new();
    for c in text.trim().chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let out = out.trim_matches(|c| c == '-' || c == '.');
    out.chars()
        .take(60)
        .collect::<String>()
        .trim_end_matches(['-', '.'])
        .to_owned()
}

/// A name from the folder, the title, or else the website.
fn name_for(folder: Option<&str>, title: &str, url: Option<&str>, kind: Kind) -> String {
    let base = Some(slug(title))
        .filter(|s| !s.is_empty())
        .or_else(|| url.and_then(site::item_name))
        .unwrap_or_else(|| {
            match kind {
                Kind::Card => "card",
                Kind::Bank => "bank-account",
                Kind::Note => "note",
                Kind::Secret => "secret",
                _ => "login",
            }
            .to_owned()
        });
    let folder = folder.map(|f| {
        f.split('/')
            .map(slug)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("/")
    });
    let folder = folder.filter(|f| !f.is_empty()).or(match kind {
        Kind::Card => Some("cards".into()),
        Kind::Bank => Some("banks".into()),
        Kind::Note => Some("notes".into()),
        _ => None,
    });
    let name = match folder {
        Some(folder) => format!("{folder}/{base}"),
        None => base,
    };
    if crate::validate_name(&name).is_ok() {
        name
    } else {
        "imported".to_owned()
    }
}

// ---- Building items ----

#[derive(Default)]
struct LoginParts {
    title: String,
    folder: Option<String>,
    url: Option<String>,
    username: Option<String>,
    password: Zeroizing<String>,
    notes: Zeroizing<String>,
    otp: Option<Zeroizing<String>>,
    /// Other fields: label, value, concealed.
    extra: Vec<(String, Zeroizing<String>, bool)>,
    note_only: bool,
    /// The file had no title: `title` is the site, for display, and the
    /// name comes from the site's domain instead.
    untitled: bool,
}

fn nonempty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

impl LoginParts {
    fn into_entry(self) -> Entry {
        let is_note = self.note_only
            || (self.password.is_empty() && self.username.is_none() && self.url.is_none());
        let mut warnings = Vec::new();
        let mut item = if is_note {
            Item::note(self.notes.as_str())
        } else {
            let mut item = Item::login(
                self.username.as_deref(),
                &self.password,
                self.url.as_deref(),
            );
            item.notes = self.notes.as_str().to_owned();
            item
        };
        if let Some(otp) = self.otp.filter(|o| !o.trim().is_empty()) {
            match otp::Totp::parse(&otp) {
                Ok(_) if !is_note => item.set(OTP_LABEL, FieldKind::Otp, otp.trim()),
                Ok(_) => warnings.push("its 2FA secret was left out (notes don't hold 2FA)".into()),
                Err(e) => warnings.push(format!("its 2FA secret was left out ({e})")),
            }
        }
        for (label, value, concealed) in self.extra {
            let label = label.trim().to_lowercase();
            if label.is_empty() || value.trim().is_empty() || item.labeled(&label).is_some() {
                continue;
            }
            let kind = if concealed {
                FieldKind::Concealed
            } else {
                FieldKind::Text
            };
            item.set(&label, kind, value.trim());
        }
        let kind = item.kind;
        let titled = if self.untitled {
            ""
        } else {
            self.title.as_str()
        };
        Entry {
            name: name_for(self.folder.as_deref(), titled, self.url.as_deref(), kind),
            title: self.title,
            item,
            warnings,
        }
    }
}

/// "8" and "2027" (or "27") → "08/27".
fn expiry(month: Option<&str>, year: Option<&str>) -> Option<String> {
    let month: u32 = month?.trim().parse().ok()?;
    let year = year?.trim();
    let year = year.get(year.len().saturating_sub(2)..)?;
    Some(format!("{month:02}/{year}"))
}

// ---- CSV ----

/// RFC 4180: quoted fields, doubled quotes, and newlines inside quotes.
fn csv_rows(text: &str) -> Vec<Vec<Zeroizing<String>>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = Zeroizing::new(String::new());
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            '"' => quoted = !quoted,
            ',' if !quoted => row.push(std::mem::take(&mut field)),
            '\r' if !quoted => {}
            '\n' if !quoted => {
                row.push(std::mem::take(&mut field));
                if !(row.len() == 1 && row[0].is_empty()) {
                    rows.push(std::mem::take(&mut row));
                }
                row.clear();
            }
            c => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

fn csv_export(text: &str) -> Result<Import, Error> {
    let mut rows = csv_rows(text).into_iter();
    let header: Vec<String> = rows
        .next()
        .ok_or_else(|| invalid("the file is empty"))?
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let col = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| header.iter().position(|h| h == n))
    };
    let title = col(&["title", "name"]);
    let url = col(&[
        "url",
        "login_uri",
        "website",
        "web site",
        "login url",
        "uri",
    ]);
    let username = col(&["username", "login_username", "user name", "login"]);
    let email = col(&["email", "e-mail"]);
    let password = col(&["password", "login_password"]);
    let notes = col(&["notes", "note", "extra", "comments", "comment"]);
    let otp = col(&["otpauth", "totp", "login_totp", "otp", "one-time password"]);
    let folder = col(&["folder", "grouping", "group"]);
    let kind = col(&["type"]);
    if password.is_none() || (url.is_none() && username.is_none() && title.is_none()) {
        return Err(invalid(
            "this CSV doesn't look like a password export (no password and website or username columns)",
        ));
    }

    let format = if header == ["title", "url", "username", "password", "notes", "otpauth"] {
        "Safari or Apple Passwords"
    } else if header.iter().any(|h| h == "httprealm") {
        "Firefox"
    } else if header.iter().any(|h| h == "login_uri") {
        "Bitwarden (CSV)"
    } else if header.iter().any(|h| h == "grouping") {
        "LastPass"
    } else if header.starts_with(&[
        "name".into(),
        "url".into(),
        "username".into(),
        "password".into(),
    ]) {
        "Chrome, Brave, Edge, or Arc"
    } else {
        "CSV"
    };

    let mut import = Import {
        format: format.into(),
        ..Import::default()
    };
    for (i, row) in rows.enumerate() {
        let get = |c: Option<usize>| c.and_then(|c| row.get(c)).map(|v| v.as_str());
        let url_value = nonempty(get(url));
        let kind_value = get(kind).unwrap_or("").trim().to_lowercase();
        let parts = LoginParts {
            untitled: nonempty(get(title)).is_none(),
            title: nonempty(get(title))
                .or_else(|| url_value.as_deref().and_then(site::display_host))
                .unwrap_or_else(|| format!("row {}", i + 2)),
            folder: nonempty(get(folder)),
            // LastPass marks secure notes with this pseudo-URL.
            note_only: url_value.as_deref() == Some("http://sn")
                || matches!(kind_value.as_str(), "note" | "securenote" | "secure note"),
            url: url_value.filter(|u| u != "http://sn"),
            username: nonempty(get(username)).or_else(|| nonempty(get(email))),
            password: Zeroizing::new(get(password).unwrap_or("").to_owned()),
            notes: Zeroizing::new(get(notes).unwrap_or("").trim().to_owned()),
            otp: get(otp).map(|o| Zeroizing::new(o.to_owned())),
            extra: Vec::new(),
        };
        if parts.password.is_empty() && parts.notes.is_empty() && parts.username.is_none() {
            import.skipped.push(Skipped {
                title: parts.title,
                why: "it's empty".into(),
            });
            continue;
        }
        import.entries.push(parts.into_entry());
    }
    Ok(import)
}

// ---- Bitwarden (JSON) ----

fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn bitwarden(text: &str) -> Result<Import, Error> {
    let root: Value = serde_json::from_str(text)
        .map_err(|e| invalid(&format!("this JSON can't be read: {e}")))?;
    if root.get("encrypted").and_then(Value::as_bool) == Some(true) {
        return Err(invalid(
            "this Bitwarden export is encrypted; export again as .json (not \"encrypted\")",
        ));
    }
    let items = root
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("this JSON isn't a Bitwarden export (no `items`)"))?;
    let folders: HashMap<&str, &str> = root
        .get("folders")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|f| Some((str_at(f, "id")?, str_at(f, "name")?)))
        .collect();

    let mut import = Import {
        format: "Bitwarden".into(),
        ..Import::default()
    };
    for item in items {
        let title = str_at(item, "name").unwrap_or("untitled").to_owned();
        let folder = str_at(item, "folderId")
            .and_then(|id| folders.get(id))
            .map(|f| (*f).to_owned());
        let notes = Zeroizing::new(str_at(item, "notes").unwrap_or("").to_owned());
        // Custom fields: type 0 text, 1 hidden, 2 checkbox, 3 linked.
        let extra: Vec<(String, Zeroizing<String>, bool)> = item
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|f| f.get("type").and_then(Value::as_u64) != Some(3))
            .filter_map(|f| {
                Some((
                    str_at(f, "name")?.to_owned(),
                    Zeroizing::new(f.get("value").map(json_text).unwrap_or_default()),
                    f.get("type").and_then(Value::as_u64) == Some(1),
                ))
            })
            .collect();
        match item.get("type").and_then(Value::as_u64) {
            Some(1) => {
                let login = item.get("login").cloned().unwrap_or(Value::Null);
                let url = login
                    .get("uris")
                    .and_then(Value::as_array)
                    .and_then(|u| u.first())
                    .and_then(|u| str_at(u, "uri"))
                    .and_then(|u| nonempty(Some(u)));
                import.entries.push(
                    LoginParts {
                        title,
                        folder,
                        url,
                        username: nonempty(str_at(&login, "username")),
                        password: Zeroizing::new(
                            str_at(&login, "password").unwrap_or("").to_owned(),
                        ),
                        notes,
                        otp: str_at(&login, "totp").map(|o| Zeroizing::new(o.to_owned())),
                        extra,
                        note_only: false,
                        untitled: false,
                    }
                    .into_entry(),
                );
            }
            Some(2) => import.entries.push(
                LoginParts {
                    title,
                    folder,
                    notes,
                    extra,
                    note_only: true,
                    ..LoginParts::default()
                }
                .into_entry(),
            ),
            Some(3) => {
                let card = item.get("card").cloned().unwrap_or(Value::Null);
                let expiry = expiry(str_at(&card, "expMonth"), str_at(&card, "expYear"));
                let built = Item::card(&CardDetails {
                    cardholder: str_at(&card, "cardholderName"),
                    number: str_at(&card, "number").unwrap_or(""),
                    expiry: expiry.as_deref(),
                    cvv: str_at(&card, "code"),
                    ..CardDetails::default()
                });
                push_built(&mut import, title, folder, notes, built);
            }
            Some(4) => {
                // An identity: its details as a note.
                let identity = item.get("identity").cloned().unwrap_or(Value::Null);
                let mut text = notes.as_str().to_owned();
                if let Some(map) = identity.as_object() {
                    for (key, value) in map {
                        let value = json_text(value);
                        if !value.is_empty() {
                            text.push_str(&format!("\n{key}: {value}"));
                        }
                    }
                }
                import.entries.push(
                    LoginParts {
                        title,
                        folder,
                        notes: Zeroizing::new(text.trim().to_owned()),
                        extra,
                        note_only: true,
                        ..LoginParts::default()
                    }
                    .into_entry(),
                );
            }
            _ => import.skipped.push(Skipped {
                title,
                why: "stash doesn't import this kind of Bitwarden item".into(),
            }),
        }
    }
    Ok(import)
}

/// A JSON value as text: strings as they are, numbers and booleans printed.
fn json_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Add a card or bank account, or list why it couldn't be.
fn push_built(
    import: &mut Import,
    title: String,
    folder: Option<String>,
    notes: Zeroizing<String>,
    built: Result<Item, Error>,
) {
    match built {
        Ok(mut item) => {
            item.notes = notes.as_str().to_owned();
            let kind = item.kind;
            import.entries.push(Entry {
                name: name_for(folder.as_deref(), &title, None, kind),
                title,
                item,
                warnings: Vec::new(),
            });
        }
        Err(e) => import.skipped.push(Skipped {
            title,
            why: e.to_string(),
        }),
    }
}

// ---- 1Password (.1pux) ----

/// 1Password item categories (`categoryUuid`).
mod category {
    pub const LOGIN: &str = "001";
    pub const CARD: &str = "002";
    pub const NOTE: &str = "003";
    pub const PASSWORD: &str = "005";
    pub const BANK: &str = "101";
    pub const API_CREDENTIAL: &str = "112";
    pub const SSH_KEY: &str = "114";
}

/// A 1Password field: its id, title, value as text, and whether it's
/// concealed.
struct OpField {
    id: String,
    title: String,
    value: Zeroizing<String>,
    concealed: bool,
    totp: bool,
}

/// A 1Password field value is an object with one key naming its type:
/// `{"concealed": "..."}`, `{"monthYear": 202708}`, `{"email": {...}}`.
fn op_value(value: &Value) -> Option<(String, Zeroizing<String>)> {
    let (kind, inner) = value.as_object()?.iter().next()?;
    let text = match inner {
        Value::String(s) => s.clone(),
        Value::Number(n) if kind == "monthYear" => {
            let n = n.as_u64()?;
            // YYYYMM → MM/YY
            format!("{:02}/{:02}", n % 100, (n / 100) % 100)
        }
        Value::Number(n) => n.to_string(),
        Value::Object(map) => map.values().find_map(Value::as_str)?.to_owned(),
        _ => return None,
    };
    Some((kind.clone(), Zeroizing::new(text)))
}

fn op_fields(details: &Value) -> Vec<OpField> {
    let mut out = Vec::new();
    for section in details
        .get("sections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for field in section
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some((kind, value)) = field.get("value").and_then(op_value) else {
                continue;
            };
            if value.trim().is_empty() {
                continue;
            }
            out.push(OpField {
                id: str_at(field, "id").unwrap_or("").to_owned(),
                title: str_at(field, "title").unwrap_or("").to_owned(),
                concealed: kind == "concealed",
                totp: kind == "totp",
                value,
            });
        }
    }
    out
}

/// The field whose id or title matches one of these (case-insensitive).
fn op_find<'a>(fields: &'a [OpField], keys: &[&str]) -> Option<&'a str> {
    fields
        .iter()
        .find(|f| {
            let id = f.id.to_lowercase();
            let title = f.title.to_lowercase();
            keys.iter().any(|k| id == *k || title == *k)
        })
        .map(|f| f.value.as_str())
}

fn one_password(bytes: &[u8]) -> Result<Import, Error> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| invalid(&format!("this .1pux can't be opened: {e}")))?;
    let mut data = Zeroizing::new(String::new());
    zip.by_name("export.data")
        .map_err(|_| invalid("this zip isn't a 1Password export (no export.data)"))?
        .read_to_string(&mut data)
        .map_err(|e| invalid(&format!("this .1pux can't be read: {e}")))?;
    let root: Value = serde_json::from_str(&data)
        .map_err(|e| invalid(&format!("this .1pux can't be read: {e}")))?;

    let vaults: Vec<&Value> = root
        .get("accounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|a| {
            a.get("vaults")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .collect();
    let mut import = Import {
        format: "1Password".into(),
        ..Import::default()
    };
    // With several vaults, each becomes a folder; with one, none is needed.
    let several = vaults.len() > 1;
    for vault in vaults {
        let vault_name = vault
            .get("attrs")
            .and_then(|a| str_at(a, "name"))
            .unwrap_or("vault");
        let folder = several.then(|| vault_name.to_owned());
        for item in vault
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let overview = item.get("overview").cloned().unwrap_or(Value::Null);
            let details = item.get("details").cloned().unwrap_or(Value::Null);
            let title = str_at(&overview, "title").unwrap_or("untitled").to_owned();
            if str_at(item, "state") == Some("archived") {
                import.skipped.push(Skipped {
                    title,
                    why: "it's archived in 1Password".into(),
                });
                continue;
            }
            let notes = Zeroizing::new(str_at(&details, "notesPlain").unwrap_or("").to_owned());
            let fields = op_fields(&details);
            let url = nonempty(str_at(&overview, "url")).or_else(|| {
                overview
                    .get("urls")
                    .and_then(Value::as_array)
                    .and_then(|u| u.first())
                    .and_then(|u| nonempty(str_at(u, "url")))
            });
            match str_at(item, "categoryUuid").unwrap_or("") {
                category::LOGIN | category::PASSWORD | category::API_CREDENTIAL => {
                    let login_fields = details.get("loginFields").and_then(Value::as_array);
                    let designated = |which: &str| {
                        login_fields
                            .into_iter()
                            .flatten()
                            .find(|f| str_at(f, "designation") == Some(which))
                            .and_then(|f| str_at(f, "value"))
                            .map(str::to_owned)
                    };
                    let password = designated("password")
                        .or_else(|| str_at(&details, "password").map(str::to_owned))
                        .or_else(|| {
                            op_find(&fields, &["credential", "password"]).map(str::to_owned)
                        })
                        .unwrap_or_default();
                    let username = designated("username")
                        .or_else(|| op_find(&fields, &["username"]).map(str::to_owned));
                    let otp = fields.iter().find(|f| f.totp).map(|f| f.value.clone());
                    let used = ["credential", "password", "username"];
                    let extra = fields
                        .iter()
                        .filter(|f| !f.totp && !used.contains(&f.id.to_lowercase().as_str()))
                        .map(|f| {
                            let label = if f.title.is_empty() { &f.id } else { &f.title };
                            (label.clone(), f.value.clone(), f.concealed)
                        })
                        .collect();
                    import.entries.push(
                        LoginParts {
                            title,
                            folder: folder.clone(),
                            url,
                            username: nonempty(username.as_deref()),
                            password: Zeroizing::new(password),
                            notes,
                            otp,
                            extra,
                            note_only: false,
                            untitled: false,
                        }
                        .into_entry(),
                    );
                }
                category::CARD => {
                    let built = Item::card(&CardDetails {
                        cardholder: op_find(
                            &fields,
                            &["cardholder", "cardholder name", "name on card"],
                        ),
                        number: op_find(&fields, &["ccnum", "number", "card number"]).unwrap_or(""),
                        expiry: op_find(&fields, &["expiry", "expiry date", "expires"]),
                        cvv: op_find(&fields, &["cvv", "verification number", "security code"]),
                        pin: op_find(&fields, &["pin"]),
                        billing_zip: op_find(&fields, &["zip", "billing zip", "postal code"]),
                    });
                    push_built(&mut import, title, folder.clone(), notes, built);
                }
                category::BANK => {
                    let built = Item::bank(&BankDetails {
                        bank: op_find(&fields, &["bankname", "bank name"]),
                        holder: op_find(&fields, &["owner", "name on account", "account holder"]),
                        account_type: op_find(&fields, &["accounttype", "type", "account type"])
                            .map(|t| t.trim()),
                        routing: op_find(&fields, &["routingno", "routing number"]),
                        account_number: op_find(&fields, &["accountno", "account number"]),
                        iban: op_find(&fields, &["iban"]),
                        swift: op_find(&fields, &["swift"]),
                        pin: op_find(&fields, &["telephonepin", "pin"]),
                    });
                    push_built(&mut import, title, folder.clone(), notes, built);
                }
                category::SSH_KEY => import.skipped.push(Skipped {
                    title,
                    why: "SSH keys: export the private key from 1Password, then `stash ssh import`"
                        .into(),
                }),
                other => {
                    // Notes, and kinds stash has no form for (identities,
                    // licenses, ...): a note with every field written out.
                    let mut text = notes.as_str().to_owned();
                    for f in &fields {
                        let label = if f.title.is_empty() { &f.id } else { &f.title };
                        text.push_str(&format!("\n{label}: {}", f.value.as_str()));
                    }
                    let mut entry = LoginParts {
                        title,
                        folder: folder.clone(),
                        notes: Zeroizing::new(text.trim().to_owned()),
                        note_only: true,
                        ..LoginParts::default()
                    }
                    .into_entry();
                    if other != category::NOTE {
                        entry
                            .warnings
                            .push("imported as a note (stash has no matching kind)".into());
                    }
                    import.entries.push(entry);
                }
            }
        }
    }
    Ok(import)
}

/// How many of each kind, for summaries: "12 logins, 2 cards".
pub fn summarize<'a>(items: impl IntoIterator<Item = &'a Item>) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for item in items {
        let kind = match item.kind {
            Kind::Login => "login",
            Kind::Secret => "secret",
            Kind::Note => "note",
            Kind::Card => "card",
            Kind::Bank => "bank account",
            Kind::Ssh => "SSH key",
        };
        *counts.entry(kind).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(kind, n)| format!("{n} {kind}{}", if n == 1 { "" } else { "s" }))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn value(e: &Entry, label: &str) -> String {
        e.item
            .labeled(label)
            .map(|f| f.value.clone())
            .unwrap_or_default()
    }

    #[test]
    fn reads_chrome_csv_with_quotes_and_newlines() {
        let csv = "name,url,username,password,note\n\
                   GitHub,https://github.com/login,octocat,\"pa,ss\"\"word\",\"line one\nline two\"\n\
                   ,https://www.example.co.uk/,me@x.com,pw2,\n";
        let import = read(csv.as_bytes()).unwrap();
        assert_eq!(import.format, "Chrome, Brave, Edge, or Arc");
        assert_eq!(import.entries.len(), 2);
        let gh = &import.entries[0];
        assert_eq!((gh.name.as_str(), gh.item.kind), ("github", Kind::Login));
        assert_eq!(value(gh, "password"), "pa,ss\"word");
        assert_eq!(value(gh, "username"), "octocat");
        assert_eq!(gh.item.notes, "line one\nline two");
        // No title: named after the site.
        assert_eq!(import.entries[1].name, "example.co.uk");
    }

    #[test]
    fn reads_apple_passwords_with_2fa() {
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\r\n\
                   AWS (work),https://aws.amazon.com,admin,pw,,otpauth://totp/AWS?secret=JBSWY3DPEHPK3PXP\r\n\
                   Broken 2FA,https://x.com,me,pw,,not-a-secret!\r\n";
        let import = read(csv.as_bytes()).unwrap();
        assert_eq!(import.format, "Safari or Apple Passwords");
        let aws = &import.entries[0];
        assert_eq!(aws.name, "aws-work");
        assert!(aws.item.has_otp());
        let broken = &import.entries[1];
        assert!(!broken.item.has_otp());
        assert!(broken.warnings[0].contains("2FA secret was left out"));
    }

    #[test]
    fn reads_lastpass_and_firefox_csvs() {
        let lastpass = "url,username,password,totp,extra,name,grouping,fav\n\
                        http://sn,,,,wifi password is hunter2,Home WiFi,Personal,0\n\
                        https://bank.com,me,pw,,,My Bank,Finance/US,0\n";
        let import = read(lastpass.as_bytes()).unwrap();
        assert_eq!(import.format, "LastPass");
        assert_eq!(import.entries[0].item.kind, Kind::Note);
        assert_eq!(import.entries[0].name, "personal/home-wifi");
        assert_eq!(import.entries[1].name, "finance/us/my-bank");

        let firefox = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\"\n\
                       \"https://accounts.google.com\",\"me@gmail.com\",\"pw\",,\"\",\"{1}\"\n";
        let import = read(firefox.as_bytes()).unwrap();
        assert_eq!(import.format, "Firefox");
        assert_eq!(import.entries[0].name, "google.com");
    }

    #[test]
    fn rejects_files_that_arent_exports() {
        assert!(read(b"just,some,columns\n1,2,3\n").is_err());
        assert!(read(b"").is_err());
        assert!(read(b"{\"encrypted\": true, \"data\": \"...\"}").is_err());
        assert!(read(&[0xff, 0xfe, 0x00]).is_err());
    }

    #[test]
    fn reads_bitwarden_json() {
        let json = r#"{
          "encrypted": false,
          "folders": [{"id": "f1", "name": "Work"}],
          "items": [
            {"type": 1, "name": "GitHub", "folderId": "f1", "notes": "n",
             "fields": [{"name": "Recovery email", "value": "r@x.com", "type": 0},
                        {"name": "PIN", "value": "1234", "type": 1}],
             "login": {"uris": [{"uri": "https://github.com"}], "username": "octocat",
                       "password": "pw", "totp": "JBSWY3DPEHPK3PXP"}},
            {"type": 2, "name": "Recovery codes", "notes": "a b c", "secureNote": {"type": 0}},
            {"type": 3, "name": "Visa", "card": {"cardholderName": "Samus Aran", "brand": "Visa",
             "number": "4242424242424242", "expMonth": "8", "expYear": "2027", "code": "123"}},
            {"type": 3, "name": "Typo card", "card": {"number": "4242424242424241"}},
            {"type": 4, "name": "Me", "identity": {"firstName": "Samus", "lastName": "Aran"}}
          ]
        }"#;
        let import = read(json.as_bytes()).unwrap();
        assert_eq!(import.format, "Bitwarden");
        let names: Vec<&str> = import.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "work/github",
                "notes/recovery-codes",
                "cards/visa",
                "notes/me"
            ]
        );
        let gh = &import.entries[0];
        assert!(gh.item.has_otp());
        assert_eq!(value(gh, "recovery email"), "r@x.com");
        assert_eq!(gh.item.labeled("pin").unwrap().kind, FieldKind::Concealed);
        assert_eq!(value(&import.entries[2], "expiry"), "08/27");
        assert!(import.entries[3].item.notes.contains("lastName: Aran"));
        assert_eq!(import.skipped.len(), 1);
        assert_eq!(import.skipped[0].title, "Typo card");
    }

    fn pux(data: &str) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("export.attributes", opts).unwrap();
        zip.write_all(br#"{"version": 3}"#).unwrap();
        zip.start_file("export.data", opts).unwrap();
        zip.write_all(data.as_bytes()).unwrap();
        zip.finish().unwrap();
        buf.into_inner()
    }

    #[test]
    fn reads_1password_exports() {
        let data = r#"{"accounts": [{"attrs": {"name": "me"}, "vaults": [
          {"attrs": {"name": "Personal"}, "items": [
            {"state": "active", "categoryUuid": "001",
             "overview": {"title": "GitHub", "url": "https://github.com"},
             "details": {"loginFields": [
                 {"designation": "username", "value": "octocat"},
                 {"designation": "password", "value": "pw"}],
               "notesPlain": "hi",
               "sections": [{"title": "", "fields": [
                 {"id": "TOTP_1", "title": "one-time password", "value": {"totp": "otpauth://totp/GH?secret=JBSWY3DPEHPK3PXP"}},
                 {"id": "x", "title": "Recovery email", "value": {"email": {"email_address": "r@x.com"}}}]}]}},
            {"state": "active", "categoryUuid": "002", "overview": {"title": "Visa"},
             "details": {"sections": [{"fields": [
               {"id": "cardholder", "title": "cardholder name", "value": {"string": "Samus Aran"}},
               {"id": "ccnum", "title": "number", "value": {"creditCardNumber": "4242 4242 4242 4242"}},
               {"id": "cvv", "title": "verification number", "value": {"concealed": "123"}},
               {"id": "expiry", "title": "expiry date", "value": {"monthYear": 202708}}]}]}},
            {"state": "active", "categoryUuid": "101", "overview": {"title": "Chase"},
             "details": {"sections": [{"fields": [
               {"id": "bankName", "title": "bank name", "value": {"string": "Chase"}},
               {"id": "routingNo", "title": "routing number", "value": {"string": "021000021"}},
               {"id": "accountNo", "title": "account number", "value": {"string": "000123456789"}},
               {"id": "accountType", "title": "type", "value": {"menu": "checking"}}]}]}},
            {"state": "active", "categoryUuid": "112", "overview": {"title": "OpenAI"},
             "details": {"sections": [{"fields": [
               {"id": "credential", "title": "credential", "value": {"concealed": "sk-abc"}}]}]}},
            {"state": "active", "categoryUuid": "106", "overview": {"title": "Passport"},
             "details": {"sections": [{"fields": [
               {"id": "number", "title": "number", "value": {"string": "X123"}}]}]}},
            {"state": "active", "categoryUuid": "114", "overview": {"title": "Deploy key"}, "details": {}},
            {"state": "archived", "categoryUuid": "001", "overview": {"title": "Old"}, "details": {}}
          ]}]}]}"#;
        let import = read(&pux(data)).unwrap();
        assert_eq!(import.format, "1Password");
        let names: Vec<&str> = import.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "github",
                "cards/visa",
                "banks/chase",
                "openai",
                "notes/passport"
            ]
        );
        let gh = &import.entries[0];
        assert!(gh.item.has_otp());
        assert_eq!(value(gh, "recovery email"), "r@x.com");
        assert_eq!(value(&import.entries[1], "expiry"), "08/27");
        assert_eq!(value(&import.entries[2], "account type"), "checking");
        assert_eq!(value(&import.entries[3], "password"), "sk-abc");
        assert!(import.entries[4].warnings[0].contains("imported as a note"));
        let skipped: Vec<&str> = import.skipped.iter().map(|s| s.title.as_str()).collect();
        assert_eq!(skipped, ["Deploy key", "Old"]);
        assert_eq!(
            summarize(import.entries.iter().map(|e| &e.item)),
            "1 bank account, 1 card, 2 logins, 1 note"
        );
    }

    #[test]
    fn names_are_always_valid() {
        for title in [
            "",
            "  ",
            "日本語",
            "../../etc",
            "a/b//c",
            &"x".repeat(300),
            "Ünïcödé Bank",
        ] {
            let name = name_for(Some("../Work//"), title, None, Kind::Login);
            assert!(crate::validate_name(&name).is_ok(), "{title:?} → {name:?}");
        }
    }
}
