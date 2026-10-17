//! Items: what a vault entry holds.
//!
//! - **secret**: one value (an API token, a key). The original kind, stored
//!   in the original encoding so any bytes work.
//! - **login**: username, password, website, optional 2FA, notes.
//! - **note**: free text.
//!
//! An item is an ordered list of labeled fields, each with a type that says
//! how to treat it (concealed fields are hidden by default, `otp` fields
//! produce codes). This mirrors how 1Password models items, so the Mac app
//! can show and edit any of them the same way.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Secret,
    Login,
    Note,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Kind::Secret => "secret",
            Kind::Login => "login",
            Kind::Note => "note",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldKind {
    Text,
    Concealed,
    Url,
    Email,
    /// An `otpauth://` URI or base32 secret; references to it yield the
    /// current code.
    Otp,
}

impl FieldKind {
    /// Whether the value should be hidden unless explicitly revealed.
    pub fn is_sensitive(self) -> bool {
        matches!(self, FieldKind::Concealed | FieldKind::Otp)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub label: String,
    pub kind: FieldKind,
    pub value: String,
}

impl Field {
    pub fn new(label: &str, kind: FieldKind, value: impl Into<String>) -> Self {
        Self {
            label: label.to_owned(),
            kind,
            value: value.into(),
        }
    }
}

impl Drop for Field {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = if self.kind.is_sensitive() {
            "<concealed>"
        } else {
            &self.value
        };
        f.debug_struct("Field")
            .field("label", &self.label)
            .field("kind", &self.kind)
            .field("value", &value)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub kind: Kind,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    /// Unix seconds. 0 when unknown (items from before v0.6).
    #[serde(default)]
    pub created: u64,
    #[serde(default)]
    pub updated: u64,
}

impl Drop for Item {
    fn drop(&mut self) {
        self.notes.zeroize();
    }
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("kind", &self.kind)
            .field("fields", &self.fields)
            .field("notes", &if self.notes.is_empty() { "" } else { "<notes>" })
            .finish()
    }
}

/// What a field reference points at.
pub enum FieldValue<'a> {
    Plain(&'a str),
    /// An OTP secret; the caller turns it into the current code.
    Otp(&'a str),
}

pub const USERNAME: &str = "username";
pub const PASSWORD: &str = "password";
pub const WEBSITE: &str = "website";
pub const ONE_TIME_PASSWORD: &str = "one-time password";

impl Item {
    pub fn secret(value: impl Into<String>) -> Self {
        Self::with(
            Kind::Secret,
            vec![Field::new("value", FieldKind::Concealed, value)],
        )
    }

    pub fn login(username: Option<&str>, password: &str, url: Option<&str>) -> Self {
        let mut fields = Vec::new();
        if let Some(u) = username {
            let kind = if u.contains('@') {
                FieldKind::Email
            } else {
                FieldKind::Text
            };
            fields.push(Field::new(USERNAME, kind, u));
        }
        fields.push(Field::new(PASSWORD, FieldKind::Concealed, password));
        if let Some(url) = url {
            fields.push(Field::new(WEBSITE, FieldKind::Url, url));
        }
        Self::with(Kind::Login, fields)
    }

    pub fn note(text: impl Into<String>) -> Self {
        let mut item = Self::with(Kind::Note, Vec::new());
        item.notes = text.into();
        item
    }

    fn with(kind: Kind, fields: Vec<Field>) -> Self {
        Self {
            kind,
            fields,
            notes: String::new(),
            created: 0,
            updated: 0,
        }
    }

    /// The value `stash get` and plain `stash://name` references return: a
    /// login's password, a note's text, a secret's value.
    pub fn primary(&self) -> Option<&str> {
        match self.kind {
            Kind::Note => Some(&self.notes),
            Kind::Login => self
                .labeled(PASSWORD)
                .or_else(|| self.fields.iter().find(|f| f.kind == FieldKind::Concealed))
                .map(|f| f.value.as_str()),
            Kind::Secret => self.fields.first().map(|f| f.value.as_str()),
        }
    }

    /// Look up a field the way references do (`stash://github#username`).
    ///
    /// Labels match ignoring case, spaces, `-`, and `_`. A few names also
    /// work by type: `password` (first concealed field), `username` (first
    /// text or email field), `url`/`website` (first URL), `otp`/`totp`/`2fa`/
    /// `code` (first one-time password), and `notes`.
    pub fn field(&self, selector: &str) -> Option<FieldValue<'_>> {
        let wanted = normalize(selector);
        if let Some(f) = self.fields.iter().find(|f| normalize(&f.label) == wanted) {
            return Some(value_of(f));
        }
        let by_kind = |pred: fn(&Field) -> bool| self.fields.iter().find(|f| pred(f)).map(value_of);
        match wanted.as_str() {
            "password" => by_kind(|f| f.kind == FieldKind::Concealed),
            "username" | "user" | "email" => {
                by_kind(|f| matches!(f.kind, FieldKind::Text | FieldKind::Email))
            }
            "url" | "website" => by_kind(|f| f.kind == FieldKind::Url),
            "otp" | "totp" | "2fa" | "code" | "onetimepassword" => {
                by_kind(|f| f.kind == FieldKind::Otp)
            }
            "notes" if !self.notes.is_empty() => Some(FieldValue::Plain(&self.notes)),
            _ => None,
        }
    }

    pub fn labeled(&self, label: &str) -> Option<&Field> {
        let wanted = normalize(label);
        self.fields.iter().find(|f| normalize(&f.label) == wanted)
    }

    /// Set a field's value, adding the field if it doesn't exist.
    pub fn set(&mut self, label: &str, kind: FieldKind, value: impl Into<String>) {
        let wanted = normalize(label);
        match self
            .fields
            .iter_mut()
            .find(|f| normalize(&f.label) == wanted)
        {
            Some(field) => {
                field.value = value.into();
                field.kind = kind;
            }
            None => self.fields.push(Field::new(label, kind, value)),
        }
    }

    /// The first username-like field, for listings.
    pub fn username(&self) -> Option<&str> {
        self.labeled(USERNAME).map(|f| f.value.as_str())
    }

    /// The first URL field, for listings.
    pub fn url(&self) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.kind == FieldKind::Url)
            .map(|f| f.value.as_str())
    }

    pub fn has_otp(&self) -> bool {
        self.fields.iter().any(|f| f.kind == FieldKind::Otp)
    }
}

fn value_of(f: &Field) -> FieldValue<'_> {
    if f.kind == FieldKind::Otp {
        FieldValue::Otp(&f.value)
    } else {
        FieldValue::Plain(&f.value)
    }
}

fn normalize(label: &str) -> String {
    label
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '_'))
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn github() -> Item {
        let mut item = Item::login(Some("octocat"), "hunter2!", Some("https://github.com"));
        item.set(ONE_TIME_PASSWORD, FieldKind::Otp, "JBSWY3DPEHPK3PXP");
        item.notes = "recovery codes in the safe".into();
        item
    }

    #[test]
    fn primary_values_by_kind() {
        assert_eq!(github().primary(), Some("hunter2!"));
        assert_eq!(Item::note("hello").primary(), Some("hello"));
        assert_eq!(Item::secret("tok").primary(), Some("tok"));
    }

    #[test]
    fn field_lookup_by_label_and_alias() {
        let item = github();
        let plain = |s: &str| match item.field(s) {
            Some(FieldValue::Plain(v)) => Some(v.to_owned()),
            _ => None,
        };
        assert_eq!(plain("username").as_deref(), Some("octocat"));
        assert_eq!(plain("USER_NAME").as_deref(), Some("octocat"));
        assert_eq!(plain("password").as_deref(), Some("hunter2!"));
        assert_eq!(plain("url").as_deref(), Some("https://github.com"));
        assert_eq!(
            plain("notes").as_deref(),
            Some("recovery codes in the safe")
        );
        assert!(matches!(
            item.field("otp"),
            Some(FieldValue::Otp("JBSWY3DPEHPK3PXP"))
        ));
        assert!(matches!(
            item.field("one-time password"),
            Some(FieldValue::Otp(_))
        ));
        assert!(item.field("nope").is_none());
    }

    #[test]
    fn emails_are_typed_and_set_replaces_values() {
        let mut item = Item::login(Some("me@example.com"), "pw", None);
        assert_eq!(item.labeled(USERNAME).unwrap().kind, FieldKind::Email);
        item.set("Password", FieldKind::Concealed, "new");
        assert_eq!(item.primary(), Some("new"));
        assert_eq!(item.fields.len(), 2);
    }

    #[test]
    fn debug_output_never_shows_secrets() {
        let shown = format!("{:?}", github());
        assert!(!shown.contains("hunter2!"));
        assert!(!shown.contains("JBSWY3DP"));
        assert!(!shown.contains("recovery"));
        assert!(shown.contains("octocat"));
    }

    #[test]
    fn round_trips_through_json() {
        let item = github();
        let json = serde_json::to_string(&item).unwrap();
        let back: Item = serde_json::from_str(&json).unwrap();
        assert_eq!(back, item);
        assert!(json.contains(r#""kind":"login""#));
    }
}
