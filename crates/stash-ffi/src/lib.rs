//! A small C interface to the vault, for the stash iPhone app (Swift calls
//! it through `include/stash.h`). The phone uses the same vault format and
//! crypto as the Mac, from this same Rust code.
//!
//! The app is read-only for now: open a vault, list it, show an item
//! without its secret values, and reveal one value on demand.
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
use stash_core::{FieldKind, Item, Kind, Vault, payment};
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
