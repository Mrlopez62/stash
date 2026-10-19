//! Low-level cryptographic building blocks.
//!
//! Everything secret-bearing is wrapped in [`Zeroizing`] so it is wiped from
//! memory when dropped.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::Error;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;

pub type SecretKey = Zeroizing<[u8; KEY_LEN]>;

/// Argon2id cost parameters used to turn the master password into a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// 256 MiB, 3 passes, 4 lanes: about a quarter of a second per unlock on
    /// a laptop, and four times the memory an offline guesser needs per
    /// guess compared with stash before v0.12 (which used 64 MiB). Vaults
    /// with weaker settings are re-wrapped with these on their next master
    /// password unlock.
    fn default() -> Self {
        Self {
            m_cost_kib: 256 * 1024,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N], Error> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| Error::Rng)?;
    Ok(buf)
}

pub fn random_key() -> Result<SecretKey, Error> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(key.as_mut()).map_err(|_| Error::Rng)?;
    Ok(key)
}

/// Derive a key-encryption key from the master password with Argon2id.
pub fn derive_kek(password: &[u8], salt: &[u8], params: KdfParams) -> Result<SecretKey, Error> {
    let params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|e| Error::Corrupt(format!("invalid KDF parameters: {e}")))?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|e| Error::Corrupt(format!("key derivation failed: {e}")))?;
    Ok(out)
}

/// Encrypt with XChaCha20-Poly1305. Returns `nonce || ciphertext`.
pub fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let nonce: [u8; NONCE_LEN] = random_bytes()?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by [`seal`]. Fails if the key, AAD, or blob is wrong.
pub fn open(key: &[u8; KEY_LEN], aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if blob.len() < NONCE_LEN {
        return Err(Error::Decrypt);
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Decrypt)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

/// HMAC-SHA256, used to derive subkeys and opaque item ids.
pub fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Constant-time equality, so comparisons don't leak how many bytes matched.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Lowercase hex encoding, for passing keys between processes.
pub fn to_hex(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for b in bytes {
        out.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(b & 0xf)]));
    }
    out
}

/// Decode a 32-byte key from hex. Returns `None` on any malformed input.
pub fn key_from_hex(hex: &str) -> Option<SecretKey> {
    let hex = hex.trim().as_bytes();
    if hex.len() != KEY_LEN * 2 {
        return None;
    }
    let nibble = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    for (i, pair) in hex.as_chunks::<2>().0.iter().enumerate() {
        key[i] = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_then_open_round_trips() {
        let key = random_key().unwrap();
        let blob = seal(&key, b"aad", b"hello").unwrap();
        assert_eq!(open(&key, b"aad", &blob).unwrap().as_slice(), b"hello");
    }

    #[test]
    fn open_rejects_wrong_aad_or_key() {
        let key = random_key().unwrap();
        let blob = seal(&key, b"aad", b"hello").unwrap();
        assert!(matches!(open(&key, b"other", &blob), Err(Error::Decrypt)));
        let other = random_key().unwrap();
        assert!(matches!(open(&other, b"aad", &blob), Err(Error::Decrypt)));
    }

    #[test]
    fn open_rejects_truncated_blob() {
        let key = random_key().unwrap();
        assert!(matches!(open(&key, b"", &[0u8; 10]), Err(Error::Decrypt)));
    }

    #[test]
    fn hex_round_trips_and_rejects_garbage() {
        let key = random_key().unwrap();
        let hex = to_hex(key.as_ref());
        assert_eq!(*key_from_hex(&hex).unwrap(), *key);
        assert!(key_from_hex("abc").is_none());
        assert!(key_from_hex(&"zz".repeat(KEY_LEN)).is_none());
    }

    #[test]
    fn ct_eq_compares_contents() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
