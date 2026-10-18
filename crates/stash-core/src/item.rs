//! Items: what a vault entry holds.
//!
//! - **secret**: one value (an API token, a key). The original kind, stored
//!   in the original encoding so any bytes work.
//! - **login**: username, password, website, optional 2FA, notes.
//! - **note**: free text.
//! - **card**: a payment card (number, expiry, security code, PIN).
//! - **bank**: a bank account (routing and account numbers, IBAN, SWIFT).
//! - **ssh**: an Ed25519 SSH key, for the SSH agent and git signing.
//!
//! An item is an ordered list of labeled fields, each with a type that says
//! how to treat it (concealed fields are hidden by default, `otp` fields
//! produce codes). This mirrors how 1Password models items, so the Mac app
//! can show and edit any of them the same way.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{Error, payment, ssh};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Secret,
    Login,
    Note,
    Card,
    Bank,
    Ssh,
}

impl Kind {
    /// Cards and bank accounts: kept away from AI agents unless allowed.
    pub fn is_payment(self) -> bool {
        matches!(self, Kind::Card | Kind::Bank)
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Kind::Secret => "secret",
            Kind::Login => "login",
            Kind::Note => "note",
            Kind::Card => "card",
            Kind::Bank => "bank",
            Kind::Ssh => "ssh",
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
pub const CARDHOLDER: &str = "cardholder";
pub const CARD_NUMBER: &str = "number";
pub const EXPIRY: &str = "expiry";
pub const CVV: &str = "cvv";
pub const PIN: &str = "pin";
pub const BILLING_ZIP: &str = "billing zip";
pub const BANK_NAME: &str = "bank";
pub const ACCOUNT_HOLDER: &str = "account holder";
pub const ACCOUNT_TYPE: &str = "account type";
pub const ROUTING_NUMBER: &str = "routing number";
pub const ACCOUNT_NUMBER: &str = "account number";
pub const IBAN: &str = "iban";
pub const SWIFT: &str = "swift";
pub const PRIVATE_KEY: &str = "private key";
pub const PUBLIC_KEY: &str = "public key";
pub const FINGERPRINT: &str = "fingerprint";

/// The parts of a payment card, as entered.
#[derive(Default)]
pub struct CardDetails<'a> {
    pub cardholder: Option<&'a str>,
    pub number: &'a str,
    pub expiry: Option<&'a str>,
    pub cvv: Option<&'a str>,
    pub pin: Option<&'a str>,
    pub billing_zip: Option<&'a str>,
}

/// The parts of a bank account, as entered.
#[derive(Default)]
pub struct BankDetails<'a> {
    pub bank: Option<&'a str>,
    pub holder: Option<&'a str>,
    pub account_type: Option<&'a str>,
    pub routing: Option<&'a str>,
    pub account_number: Option<&'a str>,
    pub iban: Option<&'a str>,
    pub swift: Option<&'a str>,
    pub pin: Option<&'a str>,
}

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

    /// A payment card, validated and normalized: digits-only number,
    /// expiry as MM/YY.
    pub fn card(c: &CardDetails<'_>) -> Result<Self, Error> {
        let mut fields = Vec::new();
        let mut push = |label: &str, kind: FieldKind, value: Option<&str>| {
            if let Some(v) = value.map(str::trim).filter(|v| !v.is_empty()) {
                fields.push(Field::new(label, kind, v));
            }
        };
        push(CARDHOLDER, FieldKind::Text, c.cardholder);
        let number = payment::digits(c.number);
        push(CARD_NUMBER, FieldKind::Concealed, Some(&number));
        let expiry = c
            .expiry
            .map(payment::parse_expiry)
            .transpose()?
            .map(|(m, y)| payment::format_expiry(m, y));
        push(EXPIRY, FieldKind::Text, expiry.as_deref());
        push(CVV, FieldKind::Concealed, c.cvv);
        push(PIN, FieldKind::Concealed, c.pin);
        push(BILLING_ZIP, FieldKind::Text, c.billing_zip);
        let item = Self::with(Kind::Card, fields);
        item.validate()?;
        Ok(item)
    }

    /// A bank account, validated: routing checksum and IBAN mod-97.
    pub fn bank(b: &BankDetails<'_>) -> Result<Self, Error> {
        let mut fields = Vec::new();
        let mut push = |label: &str, kind: FieldKind, value: Option<&str>| {
            if let Some(v) = value.map(str::trim).filter(|v| !v.is_empty()) {
                fields.push(Field::new(label, kind, v));
            }
        };
        push(BANK_NAME, FieldKind::Text, b.bank);
        push(ACCOUNT_HOLDER, FieldKind::Text, b.holder);
        push(ACCOUNT_TYPE, FieldKind::Text, b.account_type);
        push(
            ROUTING_NUMBER,
            FieldKind::Text,
            b.routing.map(payment::digits).as_deref(),
        );
        push(ACCOUNT_NUMBER, FieldKind::Concealed, b.account_number);
        let iban = b.iban.map(|i| {
            i.chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_uppercase()
        });
        push(IBAN, FieldKind::Concealed, iban.as_deref());
        push(
            SWIFT,
            FieldKind::Text,
            b.swift.map(str::to_uppercase).as_deref(),
        );
        push(PIN, FieldKind::Concealed, b.pin);
        let item = Self::with(Kind::Bank, fields);
        item.validate()?;
        Ok(item)
    }

    /// An SSH key item. Its public key and fingerprint are derived from the
    /// private key (on every save, too), so they can't disagree.
    pub fn ssh_key(pair: &ssh::KeyPair) -> Self {
        let mut item = Self::with(
            Kind::Ssh,
            vec![Field::new(
                PRIVATE_KEY,
                FieldKind::Concealed,
                pair.to_openssh().as_str(),
            )],
        );
        item.normalize();
        item
    }

    /// The key pair in an SSH key item.
    pub fn ssh_key_pair(&self) -> Result<ssh::KeyPair, Error> {
        let text = self
            .labeled(PRIVATE_KEY)
            .ok_or_else(|| Error::InvalidSshKey("an SSH key item needs its private key".into()))?;
        ssh::KeyPair::from_openssh(&text.value, None)
    }

    /// Put payment fields in their canonical form (digits-only card and
    /// routing numbers, MM/YY expiry, compact uppercase IBAN). Done on every
    /// save, so edits from any client end up the same as new items.
    pub fn normalize(&mut self) {
        if self.kind == Kind::Ssh {
            self.derive_ssh_fields();
            return;
        }
        if !self.kind.is_payment() {
            return;
        }
        for field in &mut self.fields {
            let normalized = match field.label.as_str() {
                CARD_NUMBER | ROUTING_NUMBER => Some(payment::digits(&field.value)),
                EXPIRY => payment::parse_expiry(&field.value)
                    .ok()
                    .map(|(m, y)| payment::format_expiry(m, y)),
                IBAN => Some(
                    field
                        .value
                        .chars()
                        .filter(|c| !c.is_whitespace())
                        .collect::<String>()
                        .to_uppercase(),
                ),
                SWIFT => Some(field.value.trim().to_uppercase()),
                _ => None,
            };
            if let Some(v) = normalized.filter(|v| *v != field.value) {
                field.value.zeroize();
                field.value = v;
            }
        }
    }

    fn derive_ssh_fields(&mut self) {
        let Ok(pair) = self.ssh_key_pair() else {
            return;
        };
        let derived = [
            (PUBLIC_KEY, pair.public_line()),
            (FINGERPRINT, pair.fingerprint()),
        ];
        for (label, value) in derived {
            match self.fields.iter_mut().find(|f| f.label == label) {
                Some(f) => {
                    f.kind = FieldKind::Text;
                    f.value = value;
                }
                None => self.fields.push(Field::new(label, FieldKind::Text, value)),
            }
        }
    }

    /// Check a card's, bank account's, or SSH key's fields. Other kinds
    /// always pass.
    pub fn validate(&self) -> Result<(), Error> {
        let value = |label: &str| self.labeled(label).map(|f| f.value.as_str());
        match self.kind {
            Kind::Card => {
                let number = value(CARD_NUMBER)
                    .ok_or_else(|| Error::InvalidPayment("a card needs its number".into()))?;
                let brand = payment::validate_card_number(number)?;
                if let Some(expiry) = value(EXPIRY) {
                    payment::parse_expiry(expiry)?;
                }
                if let Some(cvv) = value(CVV) {
                    payment::validate_cvv(cvv, brand)?;
                }
                Ok(())
            }
            Kind::Bank => {
                if value(ACCOUNT_NUMBER).is_none() && value(IBAN).is_none() {
                    return Err(Error::InvalidPayment(
                        "a bank account needs an account number or an IBAN".into(),
                    ));
                }
                if let Some(routing) = value(ROUTING_NUMBER) {
                    payment::validate_routing(routing)?;
                }
                if let Some(iban) = value(IBAN) {
                    payment::validate_iban(iban)?;
                }
                Ok(())
            }
            Kind::Ssh => self.ssh_key_pair().map(|_| ()),
            _ => Ok(()),
        }
    }

    /// A one-line description with nothing sensitive in it, for lists:
    /// "Visa •••• 4242 · 08/27", "Chase · Checking •••• 6789".
    pub fn subtitle(&self) -> Option<String> {
        let value = |label: &str| self.labeled(label).map(|f| f.value.as_str());
        match self.kind {
            Kind::Card => {
                let number = value(CARD_NUMBER)?;
                let mut s = format!(
                    "{} •••• {}",
                    payment::brand(number).name(),
                    payment::last4(number)
                );
                if let Some(expiry) = value(EXPIRY) {
                    s.push_str(&format!(" · {expiry}"));
                }
                Some(s)
            }
            Kind::Bank => {
                let tail = value(ACCOUNT_NUMBER).or(value(IBAN)).map(payment::last4);
                let parts: Vec<String> = [
                    value(BANK_NAME).map(str::to_owned),
                    match (value(ACCOUNT_TYPE), tail) {
                        (Some(t), Some(l)) => Some(format!("{} •••• {l}", capitalize(t))),
                        (None, Some(l)) => Some(format!("•••• {l}")),
                        (Some(t), None) => Some(capitalize(t)),
                        (None, None) => None,
                    },
                ]
                .into_iter()
                .flatten()
                .collect();
                (!parts.is_empty()).then(|| parts.join(" · "))
            }
            Kind::Ssh => {
                let fp = value(FINGERPRINT)?;
                Some(format!("Ed25519 · {}…", &fp[..fp.len().min(19)]))
            }
            _ => None,
        }
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
            Kind::Card => self.labeled(CARD_NUMBER).map(|f| f.value.as_str()),
            Kind::Bank => self
                .labeled(ACCOUNT_NUMBER)
                .or_else(|| self.labeled(IBAN))
                .map(|f| f.value.as_str()),
            Kind::Ssh => self.labeled(PRIVATE_KEY).map(|f| f.value.as_str()),
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
        // Common names for payment fields.
        let alias = match wanted.as_str() {
            "cardnumber" | "card" | "pan" => Some(CARD_NUMBER),
            "cvc" | "csc" | "securitycode" | "cvv2" => Some(CVV),
            "exp" | "expiration" | "expirationdate" | "expires" => Some(EXPIRY),
            "name" | "nameoncard" | "holder" if self.kind == Kind::Card => Some(CARDHOLDER),
            "zip" | "postcode" | "postalcode" => Some(BILLING_ZIP),
            "account" | "accountno" => Some(ACCOUNT_NUMBER),
            "routing" | "aba" | "routingno" => Some(ROUTING_NUMBER),
            "bic" | "swiftcode" => Some(SWIFT),
            _ => None,
        };
        if let Some(f) = alias.and_then(|label| self.labeled(label)) {
            return Some(value_of(f));
        }
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

    /// Set a field's value and kind, adding the field if it doesn't exist.
    pub fn set(&mut self, label: &str, kind: FieldKind, value: impl Into<String>) {
        let wanted = normalize(label);
        match self
            .fields
            .iter_mut()
            .find(|f| normalize(&f.label) == wanted)
        {
            Some(field) => {
                // Wipe the old value before it's freed.
                field.value.zeroize();
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

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map_or_else(String::new, |f| f.to_uppercase().chain(c).collect())
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

    fn visa() -> Item {
        Item::card(&CardDetails {
            cardholder: Some("J Lopez"),
            number: "4242 4242 4242 4242",
            expiry: Some("8/2027"),
            cvv: Some("123"),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn cards_are_normalized_and_summarized_safely() {
        let card = visa();
        assert_eq!(card.primary(), Some("4242424242424242"));
        assert_eq!(card.labeled(EXPIRY).unwrap().value, "08/27");
        assert_eq!(card.subtitle().as_deref(), Some("Visa •••• 4242 · 08/27"));
        let plain = |s: &str| match card.field(s) {
            Some(FieldValue::Plain(v)) => v.to_owned(),
            _ => panic!("{s}"),
        };
        assert_eq!(plain("cvc"), "123");
        assert_eq!(plain("expiration"), "08/27");
        assert_eq!(plain("card number"), "4242424242424242");
        assert_eq!(plain("name"), "J Lopez");
        assert!(!format!("{card:?}").contains("4242424242424242"));
    }

    #[test]
    fn bad_cards_are_refused() {
        let base = || CardDetails {
            number: "4242424242424242",
            ..Default::default()
        };
        assert!(
            Item::card(&CardDetails {
                number: "4242424242424241",
                ..base()
            })
            .is_err()
        );
        assert!(
            Item::card(&CardDetails {
                expiry: Some("13/27"),
                ..base()
            })
            .is_err()
        );
        assert!(
            Item::card(&CardDetails {
                cvv: Some("12"),
                ..base()
            })
            .is_err()
        );
        assert!(Item::card(&base()).is_ok(), "expiry and cvv are optional");
    }

    #[test]
    fn bank_accounts_validate_and_summarize() {
        let us = Item::bank(&BankDetails {
            bank: Some("Chase"),
            account_type: Some("checking"),
            routing: Some("021000021"),
            account_number: Some("000123456789"),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(us.primary(), Some("000123456789"));
        assert_eq!(us.subtitle().as_deref(), Some("Chase · Checking •••• 6789"));

        let eu = Item::bank(&BankDetails {
            iban: Some("gb82 west 1234 5698 7654 32"),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(eu.primary(), Some("GB82WEST12345698765432"));
        assert_eq!(eu.subtitle().as_deref(), Some("•••• 5432"));

        assert!(
            Item::bank(&BankDetails {
                bank: Some("Chase"),
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            Item::bank(&BankDetails {
                routing: Some("021000022"),
                account_number: Some("1"),
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            Item::bank(&BankDetails {
                iban: Some("GB82WEST12345698765433"),
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn ssh_keys_derive_their_public_halves() {
        let pair = crate::ssh::KeyPair::generate("me@laptop").unwrap();
        let mut item = Item::ssh_key(&pair);
        assert_eq!(item.kind, Kind::Ssh);
        let public = |item: &Item| item.labeled(PUBLIC_KEY).unwrap().value.clone();
        assert_eq!(public(&item), pair.public_line());
        assert!(item.labeled(PRIVATE_KEY).unwrap().kind.is_sensitive());
        assert!(item.subtitle().unwrap().starts_with("Ed25519 · SHA256:"));
        // A tampered public key is put back on save.
        item.fields
            .iter_mut()
            .find(|f| f.label == PUBLIC_KEY)
            .unwrap()
            .value = "ssh-ed25519 AAAAforged".into();
        item.normalize();
        assert_eq!(public(&item), pair.public_line());
        assert!(item.validate().is_ok());
        item.fields[0].value = "not a key".into();
        assert!(item.validate().is_err());
    }
}
