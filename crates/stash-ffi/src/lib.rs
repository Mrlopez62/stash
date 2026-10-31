//! A small C interface to the vault, for the stash iPhone app (Swift calls
//! it through `include/stash.h`). The phone uses the same vault format and
//! crypto as the Mac, from this same Rust code.
//!
//! The app opens a vault, lists it, shows an item without its secret values,
//! and reveals one value on demand. For a vault made on the phone, it can
//! also create the vault, and add and remove cards and bank accounts.
//!
//! Rules for callers:
//! - A `StashVault` is used from one thread at a time.
//! - Every returned string is freed with [`stash_string_free`], which wipes
//!   it first (revealed values are secrets).
//! - On failure, functions return null and set `*error` (if non-null) to a
//!   message, also freed with `stash_string_free`.

use std::ffi::{CStr, CString, c_char};
use std::path::Path;
use std::ptr;

use serde_json::{Value, json};
use stash_core::item::{BankDetails, CardDetails};
use stash_core::{FieldKind, Item, KdfParams, Kind, Vault, payment};
use zeroize::{Zeroize, Zeroizing};

/// An open vault (opaque to C).
pub struct StashVault {
    vault: Vault,
}

fn set_error(error: *mut *mut c_char, message: impl Into<String>) {
    if !error.is_null() {
        // SAFETY: the caller passed a valid `char **` (or null, checked).
        unsafe { *error = to_c(message.into()) };
    }
}

/// A Rust string as a C string the caller frees. Interior NULs are dropped.
fn to_c(mut s: String) -> *mut c_char {
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != 0).collect();
    s.zeroize();
    CString::new(bytes).map_or(ptr::null_mut(), CString::into_raw)
}

/// SAFETY: `s` is null or a valid NUL-terminated string.
unsafe fn from_c<'a>(s: *const c_char) -> Option<&'a str> {
    if s.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(s) }.to_str().ok()
}

fn boxed(vault: Vault) -> *mut StashVault {
    Box::into_raw(Box::new(StashVault { vault }))
}

/// Whether the file at `path` is a current stash vault, without any
/// password. False sets `*error`.
///
/// # Safety
/// `path` is a NUL-terminated UTF-8 path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stash_check_vault(path: *const c_char, error: *mut *mut c_char) -> bool {
    let Some(path) = (unsafe { from_c(path) }) else {
        set_error(error, "invalid path");
        return false;
    };
    match Vault::check_file(Path::new(path)) {
        Ok(()) => true,
        Err(_) => {
            set_error(
                error,
                "That file isn't a stash vault from this version. On your Mac, run `stash export --phone` again.",
            );
            false
        }
    }
}

/// The shortest password a new vault accepts, as on the Mac.
const MIN_PASSWORD_LEN: usize = 8;

/// Create a new, empty vault with this password, and open it.
///
/// # Safety
/// `path` is a NUL-terminated UTF-8 path; `password` points to `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stash_create(
    path: *const c_char,
    password: *const u8,
    len: usize,
    error: *mut *mut c_char,
) -> *mut StashVault {
    let Some(path) = (unsafe { from_c(path) }) else {
        set_error(error, "invalid path");
        return ptr::null_mut();
    };
    if password.is_null() {
        set_error(error, "no password");
        return ptr::null_mut();
    }
    // SAFETY: the caller guarantees `len` readable bytes.
    let password = unsafe { std::slice::from_raw_parts(password, len) };
    let long_enough =
        std::str::from_utf8(password).is_ok_and(|p| p.chars().count() >= MIN_PASSWORD_LEN);
    if !long_enough {
        set_error(
            error,
            format!("The password must be at least {MIN_PASSWORD_LEN} characters."),
        );
        return ptr::null_mut();
    }
    match Vault::create(Path::new(path), password, KdfParams::default()) {
        Ok(vault) => boxed(vault),
        Err(e) => {
            set_error(error, e.to_string());
            ptr::null_mut()
        }
    }
}

/// A card or bank account from JSON (`{"kind": "card", "number", ...}`),
/// checked the same way as on the Mac.
fn payment_item(json: &str) -> Result<Item, String> {
    let v: Value = serde_json::from_str(json).map_err(|_| "invalid item".to_owned())?;
    let text = |key: &str| {
        v.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    let built = match text("kind") {
        Some("card") => Item::card(&CardDetails {
            cardholder: text("cardholder"),
            number: text("number").ok_or("Enter the card number.")?,
            expiry: text("expiry"),
            cvv: text("cvv"),
            pin: text("pin"),
            billing_zip: text("billing_zip"),
        }),
        Some("bank") => Item::bank(&BankDetails {
            bank: text("bank"),
            holder: text("holder"),
            account_type: text("account_type"),
            routing: text("routing"),
            account_number: text("account_number"),
            iban: text("iban"),
            swift: text("swift"),
            pin: text("pin"),
        }),
        _ => return Err("only cards and bank accounts can be added here".to_owned()),
    };
    built.map_err(|e| e.to_string())
}

/// Add a card or bank account under `name`, never replacing an item. `json`
/// describes it (see `payment_item`). False sets `*error`.
///
/// # Safety
/// `vault` came from a `stash_open_*` or `stash_create` call and holds no
/// other reference; `name` and `json` are NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stash_add_payment(
    vault: *mut StashVault,
    name: *const c_char,
    json: *const c_char,
    error: *mut *mut c_char,
) -> bool {
    let (Some(v), Some(name), Some(json)) =
        (unsafe { vault.as_mut() }, unsafe { from_c(name) }, unsafe {
            from_c(json)
        })
    else {
        set_error(error, "invalid arguments");
        return false;
    };
    let result = payment_item(json)
        .and_then(|item| v.vault.put(name, &item, false).map_err(|e| e.to_string()));
    match result {
        Ok(()) => true,
        Err(why) => {
            set_error(error, why);
            false
        }
    }
}

/// Replace a card or bank account's details, keeping when it was created. It
/// must already exist and stay the same kind. False sets `*error`.
///
/// # Safety
/// `vault` came from a `stash_open_*` or `stash_create` call and holds no
/// other reference; `name` and `json` are NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stash_update_payment(
    vault: *mut StashVault,
    name: *const c_char,
    json: *const c_char,
    error: *mut *mut c_char,
) -> bool {
    let (Some(v), Some(name), Some(json)) =
        (unsafe { vault.as_mut() }, unsafe { from_c(name) }, unsafe {
            from_c(json)
        })
    else {
        set_error(error, "invalid arguments");
        return false;
    };
    let result = (|| {
        let old = v.vault.item(name).map_err(|e| e.to_string())?;
        let mut item = payment_item(json)?;
        if item.kind != old.kind {
            return Err("a card can't become a bank account, or the other way round".to_owned());
        }
        item.created = old.created;
        v.vault.put(name, &item, true).map_err(|e| e.to_string())
    })();
    match result {
        Ok(()) => true,
        Err(why) => {
            set_error(error, why);
            false
        }
    }
}

/// Delete an item. False sets `*error`.
///
/// # Safety
/// `vault` came from a `stash_open_*` or `stash_create` call and holds no
/// other reference; `name` is NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stash_remove(
    vault: *mut StashVault,
    name: *const c_char,
    error: *mut *mut c_char,
) -> bool {
    let (Some(v), Some(name)) = (unsafe { vault.as_mut() }, unsafe { from_c(name) }) else {
        set_error(error, "invalid arguments");
        return false;
    };
    match v.vault.remove(name) {
        Ok(()) => true,
        Err(e) => {
            set_error(error, e.to_string());
            false
        }
    }
}

/// Open a vault with its password. This unlock can read cards and bank
/// accounts. A vault in an older format is refused rather than upgraded.
///
/// # Safety
/// `path` is a NUL-terminated UTF-8 path; `password` points to `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stash_open_password(
    path: *const c_char,
    password: *const u8,
    len: usize,
    error: *mut *mut c_char,
) -> *mut StashVault {
    let Some(path) = (unsafe { from_c(path) }) else {
        set_error(error, "invalid path");
        return ptr::null_mut();
    };
    if password.is_null() {
        set_error(error, "no password");
        return ptr::null_mut();
    }
    // SAFETY: the caller guarantees `len` readable bytes.
    let password = unsafe { std::slice::from_raw_parts(password, len) };
    match Vault::open(Path::new(path), password) {
        Ok(vault) if vault.is_current() => boxed(vault),
        Ok(_) => {
            set_error(
                error,
                "this vault is in an older format; export it again from your Mac",
            );
            ptr::null_mut()
        }
        Err(e) => {
            set_error(error, e.to_string());
            ptr::null_mut()
        }
    }
}

/// Open a vault with its two keys (as saved for Face ID by
/// [`stash_copy_keys`]): `keys` is 64 bytes, the main key then the
/// sensitive key.
///
/// # Safety
/// `path` is a NUL-terminated UTF-8 path; `keys` points to 64 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stash_open_keys(
    path: *const c_char,
    keys: *const u8,
    error: *mut *mut c_char,
) -> *mut StashVault {
    let Some(path) = (unsafe { from_c(path) }) else {
        set_error(error, "invalid path");
        return ptr::null_mut();
    };
    if keys.is_null() {
        set_error(error, "no keys");
        return ptr::null_mut();
    }
    // SAFETY: the caller guarantees 64 readable bytes.
    let keys = unsafe { std::slice::from_raw_parts(keys, 64) };
    let main: Zeroizing<[u8; 32]> = Zeroizing::new(keys[..32].try_into().expect("32 bytes"));
    let sensitive: Zeroizing<[u8; 32]> = Zeroizing::new(keys[32..].try_into().expect("32 bytes"));
    let opened = Vault::open_with_key(Path::new(path), &main).and_then(|mut vault| {
        vault.unlock_sensitive_with_key(&sensitive)?;
        Ok(vault)
    });
    match opened {
        Ok(vault) => boxed(vault),
        Err(e) => {
            set_error(error, e.to_string());
            ptr::null_mut()
        }
    }
}

/// Copy the vault's two keys (64 bytes: main, then sensitive) into `out`,
/// for wrapping with a Face ID key. False if this unlock doesn't hold the
/// sensitive key.
///
/// # Safety
/// `vault` came from a `stash_open_*` call; `out` points to 64 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stash_copy_keys(vault: *const StashVault, out: *mut u8) -> bool {
    let (Some(v), false) = (unsafe { vault.as_ref() }, out.is_null()) else {
        return false;
    };
    let Some(sensitive) = v.vault.sensitive_key() else {
        return false;
    };
    // SAFETY: 64 writable bytes, per the contract.
    let out = unsafe { std::slice::from_raw_parts_mut(out, 64) };
    out[..32].copy_from_slice(v.vault.key());
    out[32..].copy_from_slice(sensitive);
    true
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Login => "login",
        Kind::Secret => "secret",
        Kind::Note => "note",
        Kind::Card => "card",
        Kind::Bank => "bank",
        Kind::Ssh => "ssh",
    }
}

/// The items, as JSON: `[{"name", "kind", "subtitle"}]`. No values.
///
/// # Safety
/// `vault` came from a `stash_open_*` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stash_list(
    vault: *const StashVault,
    error: *mut *mut c_char,
) -> *mut c_char {
    let Some(v) = (unsafe { vault.as_ref() }) else {
        set_error(error, "no vault");
        return ptr::null_mut();
    };
    match v.vault.summaries() {
        Ok(summaries) => {
            let items: Vec<Value> = summaries
                .iter()
                .map(|s| json!({ "name": s.name, "kind": kind_name(s.kind), "subtitle": s.subtitle }))
                .collect();
            to_c(Value::Array(items).to_string())
        }
        Err(e) => {
            set_error(error, e.to_string());
            ptr::null_mut()
        }
    }
}

/// For a card face: the brand and last four digits only.
fn card_face(item: &Item) -> Option<Value> {
    let number = item.primary().filter(|n| !n.is_empty())?;
    Some(json!({
        "brand": payment::brand(number).name(),
        "last4": payment::last4(number),
    }))
}

/// One item, as JSON, without secret values: `{"name", "kind",
/// "subtitle", "card": {"brand", "last4"}?, "fields": [{"label", "kind",
/// "value"?}], "has_notes"}`. Concealed fields have no `value`; reveal them
/// with [`stash_reveal`].
///
/// # Safety
/// `vault` came from a `stash_open_*` call; `name` is NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stash_item(
    vault: *const StashVault,
    name: *const c_char,
    error: *mut *mut c_char,
) -> *mut c_char {
    let (Some(v), Some(name)) = (unsafe { vault.as_ref() }, unsafe { from_c(name) }) else {
        set_error(error, "invalid arguments");
        return ptr::null_mut();
    };
    let item = match v.vault.item(name) {
        Ok(item) => item,
        Err(e) => {
            set_error(error, e.to_string());
            return ptr::null_mut();
        }
    };
    let fields: Vec<Value> = item
        .fields
        .iter()
        .map(|f| {
            let mut field = json!({ "label": f.label, "kind": f.kind });
            if !f.kind.is_sensitive() && f.kind != FieldKind::Otp {
                field["value"] = json!(f.value);
            }
            field
        })
        .collect();
    let card = (item.kind == Kind::Card)
        .then(|| card_face(&item))
        .flatten();
    to_c(
        json!({
            "name": name,
            "kind": kind_name(item.kind),
            "subtitle": item.subtitle(),
            "card": card,
            "fields": fields,
            "has_notes": !item.notes.is_empty(),
        })
        .to_string(),
    )
}

/// One value, by field label (or `notes`). Free it with
/// [`stash_string_free`], which wipes it.
///
/// # Safety
/// `vault` came from a `stash_open_*` call; `name` and `field` are
/// NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stash_reveal(
    vault: *const StashVault,
    name: *const c_char,
    field: *const c_char,
    error: *mut *mut c_char,
) -> *mut c_char {
    let (Some(v), Some(name), Some(field)) =
        (unsafe { vault.as_ref() }, unsafe { from_c(name) }, unsafe {
            from_c(field)
        })
    else {
        set_error(error, "invalid arguments");
        return ptr::null_mut();
    };
    let item = match v.vault.item(name) {
        Ok(item) => item,
        Err(e) => {
            set_error(error, e.to_string());
            return ptr::null_mut();
        }
    };
    let value = if field == "notes" {
        Some(item.notes.clone())
    } else {
        item.labeled(field)
            .filter(|f| f.kind != FieldKind::Otp)
            .map(|f| f.value.clone())
    };
    match value {
        Some(value) => to_c(value),
        None => {
            set_error(error, format!("“{name}” has no {field}"));
            ptr::null_mut()
        }
    }
}

/// Close a vault, wiping its keys.
///
/// # Safety
/// `vault` came from a `stash_open_*` call and isn't used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stash_close(vault: *mut StashVault) {
    if !vault.is_null() {
        // SAFETY: created by Box::into_raw in `boxed`.
        drop(unsafe { Box::from_raw(vault) });
    }
}

/// Wipe and free a string returned by this library.
///
/// # Safety
/// `s` is null or a string returned by this library, not freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stash_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // SAFETY: created by CString::into_raw in `to_c`.
    let s = unsafe { CString::from_raw(s) };
    let mut bytes = s.into_bytes_with_nul();
    bytes.zeroize();
}

#[cfg(test)]
mod tests {
    use stash_core::KdfParams;
    use stash_core::item::CardDetails;

    use super::*;

    fn take(s: *mut c_char) -> String {
        assert!(!s.is_null());
        let out = unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_owned();
        unsafe { stash_string_free(s) };
        out
    }

    #[test]
    fn creates_a_vault_and_adds_and_removes_payments() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("phone.stashvault");
        let c_path = CString::new(path.to_str().unwrap()).unwrap();
        let mut error: *mut c_char = ptr::null_mut();

        let short = b"short";
        assert!(
            unsafe { stash_create(c_path.as_ptr(), short.as_ptr(), short.len(), &mut error) }
                .is_null()
        );
        assert!(take(error).contains("at least 8"));
        assert!(!path.exists());

        let pw = b"phone-password";
        let v = unsafe { stash_create(c_path.as_ptr(), pw.as_ptr(), pw.len(), ptr::null_mut()) };
        assert!(!v.is_null());
        assert!(unsafe { stash_check_vault(c_path.as_ptr(), ptr::null_mut()) });

        let name = CString::new("cards/visa-4242").unwrap();
        let card = CString::new(
            r#"{"kind":"card","cardholder":"Samus Aran","number":"4242 4242 4242 4242","expiry":"08/27","cvv":"123","pin":""}"#,
        )
        .unwrap();
        assert!(unsafe { stash_add_payment(v, name.as_ptr(), card.as_ptr(), &mut error) });
        let field = CString::new("number").unwrap();
        assert_eq!(
            take(unsafe { stash_reveal(v, name.as_ptr(), field.as_ptr(), ptr::null_mut()) }),
            "4242424242424242"
        );

        // An existing item is never replaced.
        assert!(!unsafe { stash_add_payment(v, name.as_ptr(), card.as_ptr(), &mut error) });
        take(error);

        // Editing replaces the details of an item that exists, kind unchanged.
        let edited = CString::new(
            r#"{"kind":"card","cardholder":"Samus Aran","number":"5555555555554444","expiry":"09/29","cvv":"456"}"#,
        )
        .unwrap();
        assert!(unsafe { stash_update_payment(v, name.as_ptr(), edited.as_ptr(), &mut error) });
        assert_eq!(
            take(unsafe { stash_reveal(v, name.as_ptr(), field.as_ptr(), ptr::null_mut()) }),
            "5555555555554444"
        );
        let missing = CString::new("cards/missing").unwrap();
        assert!(!unsafe { stash_update_payment(v, missing.as_ptr(), edited.as_ptr(), &mut error) });
        take(error);
        let as_bank = CString::new(r#"{"kind":"bank","bank":"Chase","routing":"021000021","account_number":"000123456789"}"#).unwrap();
        assert!(!unsafe { stash_update_payment(v, name.as_ptr(), as_bank.as_ptr(), &mut error) });
        assert!(take(error).contains("can't become"));

        // A mistyped card is refused, as on the Mac.
        let typo_name = CString::new("cards/typo").unwrap();
        let typo = CString::new(r#"{"kind":"card","number":"4242424242424241"}"#).unwrap();
        assert!(!unsafe { stash_add_payment(v, typo_name.as_ptr(), typo.as_ptr(), &mut error) });
        assert!(take(error).contains("typo"));

        // Only payments can be added this way.
        let login = CString::new(r#"{"kind":"login","password":"x"}"#).unwrap();
        assert!(!unsafe { stash_add_payment(v, typo_name.as_ptr(), login.as_ptr(), &mut error) });
        take(error);

        let bank_name = CString::new("banks/chase-6789").unwrap();
        let bank = CString::new(
            r#"{"kind":"bank","bank":"Chase","routing":"021000021","account_number":"000123456789","account_type":"checking"}"#,
        )
        .unwrap();
        assert!(unsafe { stash_add_payment(v, bank_name.as_ptr(), bank.as_ptr(), &mut error) });
        let list = take(unsafe { stash_list(v, ptr::null_mut()) });
        assert!(list.contains("cards/visa-4242") && list.contains("banks/chase-6789"));

        assert!(unsafe { stash_remove(v, name.as_ptr(), &mut error) });
        assert!(!take(unsafe { stash_list(v, ptr::null_mut()) }).contains("cards/visa-4242"));
        unsafe { stash_close(v) };

        // It's a normal vault: it reopens with its password.
        let v =
            unsafe { stash_open_password(c_path.as_ptr(), pw.as_ptr(), pw.len(), ptr::null_mut()) };
        assert!(!v.is_null());
        assert!(take(unsafe { stash_list(v, ptr::null_mut()) }).contains("banks/chase-6789"));

        // Face ID opens it with the saved keys, and can still add to it.
        let mut keys = [0u8; 64];
        assert!(unsafe { stash_copy_keys(v, keys.as_mut_ptr()) });
        unsafe { stash_close(v) };
        let v = unsafe { stash_open_keys(c_path.as_ptr(), keys.as_ptr(), ptr::null_mut()) };
        assert!(!v.is_null());
        assert!(unsafe { stash_add_payment(v, name.as_ptr(), card.as_ptr(), &mut error) });
        unsafe { stash_close(v) };
    }

    #[test]
    fn opens_lists_shows_and_reveals() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("phone.stashvault");
        {
            let mut vault = Vault::create(
                &path,
                b"phone-password",
                KdfParams {
                    m_cost_kib: 8,
                    t_cost: 1,
                    p_cost: 1,
                },
            )
            .unwrap();
            let card = Item::card(&CardDetails {
                cardholder: Some("Samus Aran"),
                number: "4242424242424242",
                expiry: Some("08/27"),
                cvv: Some("123"),
                ..CardDetails::default()
            })
            .unwrap();
            vault.put("cards/visa", &card, false).unwrap();
        }
        let c_path = CString::new(path.to_str().unwrap()).unwrap();
        let mut error: *mut c_char = ptr::null_mut();

        assert!(unsafe { stash_check_vault(c_path.as_ptr(), ptr::null_mut()) });
        let junk = dir.path().join("junk.stashvault");
        std::fs::write(&junk, "not a vault").unwrap();
        let c_junk = CString::new(junk.to_str().unwrap()).unwrap();
        assert!(!unsafe { stash_check_vault(c_junk.as_ptr(), &mut error) });
        assert!(take(error).contains("isn't a stash vault"));

        let wrong =
            unsafe { stash_open_password(c_path.as_ptr(), b"nope".as_ptr(), 4, &mut error) };
        assert!(wrong.is_null());
        assert!(take(error).contains("wrong"));

        let pw = b"phone-password";
        let v =
            unsafe { stash_open_password(c_path.as_ptr(), pw.as_ptr(), pw.len(), ptr::null_mut()) };
        assert!(!v.is_null());

        let list = take(unsafe { stash_list(v, ptr::null_mut()) });
        assert!(list.contains("cards/visa") && list.contains("Visa •••• 4242"));
        assert!(!list.contains("4242424242424242"));

        let name = CString::new("cards/visa").unwrap();
        let item = take(unsafe { stash_item(v, name.as_ptr(), ptr::null_mut()) });
        assert!(item.contains("\"last4\":\"4242\"") && item.contains("Samus Aran"));
        assert!(!item.contains("4242424242424242") && !item.contains("\"123\""));

        let field = CString::new("cvv").unwrap();
        assert_eq!(
            take(unsafe { stash_reveal(v, name.as_ptr(), field.as_ptr(), ptr::null_mut()) }),
            "123"
        );

        // The keys reopen it (the Face ID path) with cards readable.
        let mut keys = [0u8; 64];
        assert!(unsafe { stash_copy_keys(v, keys.as_mut_ptr()) });
        unsafe { stash_close(v) };
        let v = unsafe { stash_open_keys(c_path.as_ptr(), keys.as_ptr(), ptr::null_mut()) };
        assert!(!v.is_null());
        let number = CString::new("number").unwrap();
        assert_eq!(
            take(unsafe { stash_reveal(v, name.as_ptr(), number.as_ptr(), ptr::null_mut()) }),
            "4242424242424242"
        );
        unsafe { stash_close(v) };

        keys[0] ^= 1;
        let bad = unsafe { stash_open_keys(c_path.as_ptr(), keys.as_ptr(), &mut error) };
        assert!(bad.is_null());
        take(error);
    }
}
