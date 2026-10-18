//! SSH keys: Ed25519 key pairs in OpenSSH's formats, and the signatures the
//! SSH agent hands out.
//!
//! - **Generating** makes a new Ed25519 key from the system's random number
//!   generator.
//! - **Importing** reads an OpenSSH private key file (`-----BEGIN OPENSSH
//!   PRIVATE KEY-----`), including passphrase-protected ones (bcrypt KDF with
//!   aes256-ctr, `ssh-keygen`'s default). Other key types are refused with a
//!   clear message; Ed25519 is what GitHub, GitLab, and `ssh-keygen` recommend.
//! - **Storing**: the vault keeps the key unencrypted *inside* the vault
//!   (the vault is the encryption), so the agent never needs a passphrase.
//!
//! Wire formats follow RFC 4251 (strings are a u32 length then bytes),
//! RFC 8709 (ssh-ed25519), and OpenSSH's PROTOCOL.key and PROTOCOL.sshsig.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::Error;

pub const KEY_TYPE: &str = "ssh-ed25519";
const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----";
const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";

fn invalid(why: impl Into<String>) -> Error {
    Error::InvalidSshKey(why.into())
}

/// An Ed25519 key pair. The secret half is wiped when dropped.
pub struct KeyPair {
    signing: SigningKey,
    pub comment: String,
}

impl KeyPair {
    pub fn generate(comment: &str) -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| Error::Rng)?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
            comment: comment.to_owned(),
        })
    }

    /// The 32-byte public key.
    pub fn public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The public key as SSH encodes it (`string "ssh-ed25519", string key`).
    pub fn public_blob(&self) -> Vec<u8> {
        public_blob(&self.public())
    }

    /// The `authorized_keys` line: `ssh-ed25519 AAAA… comment`.
    pub fn public_line(&self) -> String {
        let mut line = format!("{KEY_TYPE} {}", STANDARD.encode(self.public_blob()));
        if !self.comment.is_empty() {
            line.push(' ');
            line.push_str(&self.comment);
        }
        line
    }

    /// `SHA256:…`, as `ssh-keygen -l` and GitHub show it.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public_blob())
    }

    /// An SSH signature blob: `string "ssh-ed25519", string signature`.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature = self.signing.sign(data).to_bytes();
        let mut out = Vec::with_capacity(4 + KEY_TYPE.len() + 4 + 64);
        put_string(&mut out, KEY_TYPE.as_bytes());
        put_string(&mut out, &signature);
        out
    }

    /// The unencrypted OpenSSH private key file, which is what the vault
    /// stores. `ssh-keygen` and `ssh` read it as is.
    pub fn to_openssh(&self) -> Zeroizing<String> {
        let mut private = Zeroizing::new(Vec::new());
        // Matching check numbers tell a reader the decryption worked; they
        // have no meaning when there's no encryption.
        let check = u32::from_be_bytes(self.public()[..4].try_into().expect("4 bytes"));
        private.extend_from_slice(&check.to_be_bytes());
        private.extend_from_slice(&check.to_be_bytes());
        put_string(&mut private, KEY_TYPE.as_bytes());
        put_string(&mut private, &self.public());
        let mut secret = Zeroizing::new([0u8; 64]);
        secret[..32].copy_from_slice(self.signing.as_bytes());
        secret[32..].copy_from_slice(&self.public());
        put_string(&mut private, secret.as_ref());
        put_string(&mut private, self.comment.as_bytes());
        let mut pad = 1u8;
        while private.len() % 8 != 0 {
            private.push(pad);
            pad += 1;
        }

        let mut file = Zeroizing::new(Vec::new());
        file.extend_from_slice(AUTH_MAGIC);
        put_string(&mut file, b"none");
        put_string(&mut file, b"none");
        put_string(&mut file, b"");
        file.extend_from_slice(&1u32.to_be_bytes());
        put_string(&mut file, &self.public_blob());
        put_string(&mut file, &private);

        let body = Zeroizing::new(STANDARD.encode(file.as_slice()));
        let mut pem = Zeroizing::new(String::with_capacity(body.len() + 80));
        pem.push_str(PEM_BEGIN);
        pem.push('\n');
        for chunk in body.as_bytes().chunks(70) {
            pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            pem.push('\n');
        }
        pem.push_str(PEM_END);
        pem.push('\n');
        pem
    }

    /// Read an OpenSSH private key file. `passphrase` is only used if the
    /// file is encrypted; [`Error::SshPassphrase`] means it's needed (or
    /// wrong).
    pub fn from_openssh(text: &str, passphrase: Option<&[u8]>) -> Result<Self, Error> {
        let text = text.trim();
        if text.starts_with("-----BEGIN RSA PRIVATE KEY-----")
            || text.starts_with("-----BEGIN EC PRIVATE KEY-----")
            || text.starts_with("-----BEGIN PRIVATE KEY-----")
            || text.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        {
            return Err(invalid(
                "that's an older key format; stash imports Ed25519 keys in OpenSSH format \
                 (make one with `ssh-keygen -t ed25519`)",
            ));
        }
        if text.starts_with("ssh-") || text.starts_with("ecdsa-") {
            return Err(invalid(
                "that's a public key; import the private key file (the one without .pub)",
            ));
        }
        let body = text
            .strip_prefix(PEM_BEGIN)
            .and_then(|t| t.strip_suffix(PEM_END))
            .ok_or_else(|| invalid("not an OpenSSH private key file"))?;
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = Zeroizing::new(
            STANDARD
                .decode(compact)
                .map_err(|_| invalid("the key file is damaged (bad base64)"))?,
        );
        let mut r = Reader::new(
            bytes
                .strip_prefix(AUTH_MAGIC)
                .ok_or_else(|| invalid("not an OpenSSH private key file"))?,
        );
        let cipher = r.string()?.to_vec();
        let kdf = r.string()?.to_vec();
        let kdf_options = r.string()?.to_vec();
        if r.u32()? != 1 {
            return Err(invalid("the key file holds more than one key"));
        }
        let public_blob = r.string()?.to_vec();
        let mut private = Zeroizing::new(r.string()?.to_vec());

        let key_type = Reader::new(&public_blob).string()?.to_vec();
        if key_type != KEY_TYPE.as_bytes() {
            return Err(invalid(format!(
                "stash supports Ed25519 SSH keys; this one is {}. Make a new one with \
                 `stash ssh generate`, or `ssh-keygen -t ed25519`",
                String::from_utf8_lossy(&key_type)
            )));
        }

        match (cipher.as_slice(), kdf.as_slice()) {
            (b"none", b"none") => {}
            (b"aes256-ctr", b"bcrypt") => {
                let passphrase = passphrase.ok_or(Error::SshPassphrase)?;
                let mut opts = Reader::new(&kdf_options);
                let salt = opts.string()?.to_vec();
                let rounds = opts.u32()?;
                let mut key_iv = Zeroizing::new([0u8; 48]);
                bcrypt_pbkdf::bcrypt_pbkdf(passphrase, &salt, rounds, key_iv.as_mut())
                    .map_err(|_| invalid("the key file's encryption settings are invalid"))?;
                use ctr::cipher::{KeyIvInit, StreamCipher};
                let mut c =
                    ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&key_iv[..32], &key_iv[32..])
                        .map_err(|_| invalid("the key file's encryption settings are invalid"))?;
                c.apply_keystream(&mut private);
            }
            (cipher, _) => {
                return Err(invalid(format!(
                    "the key file is encrypted with {}, which stash can't read yet. Re-save it \
                     with `ssh-keygen -p -Z aes256-ctr -f <file>`, then import again",
                    String::from_utf8_lossy(cipher)
                )));
            }
        }

        let mut r = Reader::new(&private);
        let (check1, check2) = (r.u32()?, r.u32()?);
        if check1 != check2 {
            return Err(if passphrase.is_some() {
                Error::SshPassphrase
            } else {
                invalid("the key file is damaged")
            });
        }
        if r.string()? != KEY_TYPE.as_bytes() {
            return Err(invalid("the key file is damaged (mismatched key types)"));
        }
        let public = r.string()?.to_vec();
        let secret = r.string()?;
        if secret.len() != 64 || public.len() != 32 || secret[32..] != public[..] {
            return Err(invalid("the key file is damaged (mismatched halves)"));
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&secret[..32]);
        let comment = String::from_utf8_lossy(r.string()?).into_owned();
        let pair = Self {
            signing: SigningKey::from_bytes(&seed),
            comment,
        };
        if pair.public_blob() != public_blob {
            return Err(invalid(
                "the key file is damaged (public key doesn't match)",
            ));
        }
        Ok(pair)
    }
}

/// The public key blob for a raw Ed25519 public key.
pub fn public_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + KEY_TYPE.len() + 4 + 32);
    put_string(&mut out, KEY_TYPE.as_bytes());
    put_string(&mut out, public);
    out
}

/// The blob from an `authorized_keys` line.
pub fn blob_from_line(line: &str) -> Option<Vec<u8>> {
    let mut parts = line.split_whitespace();
    let kind = parts.next()?;
    let blob = STANDARD.decode(parts.next()?).ok()?;
    (Reader::new(&blob).string().ok()? == kind.as_bytes()).then_some(blob)
}

pub fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}

/// What a signing request is for, read from the data to be signed, so the
/// approval prompt can say it.
#[derive(Debug, PartialEq, Eq)]
pub enum SignPurpose {
    /// An SSH login (`ssh`, `git push` over SSH). Holds the remote user name.
    Login {
        user: String,
    },
    /// An `ssh-keygen -Y sign` signature. Git uses the namespace "git".
    File {
        namespace: String,
    },
    Unknown,
}

impl SignPurpose {
    pub fn of(data: &[u8]) -> Self {
        if let Some(rest) = data.strip_prefix(SSHSIG_MAGIC) {
            let namespace = Reader::new(rest)
                .string()
                .map(|n| String::from_utf8_lossy(n).into_owned())
                .unwrap_or_default();
            return SignPurpose::File { namespace };
        }
        // RFC 4252 §7: string session id, byte 50, string user, string
        // service, string "publickey", ...
        let mut r = Reader::new(data);
        let login = (|| {
            r.string().ok()?;
            if r.byte()? != 50 {
                return None;
            }
            let user = String::from_utf8_lossy(r.string().ok()?).into_owned();
            r.string().ok()?;
            (r.string().ok()? == b"publickey").then_some(user)
        })();
        match login {
            Some(user) => SignPurpose::Login { user },
            None => SignPurpose::Unknown,
        }
    }
}

pub fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Reads SSH wire data, refusing anything that runs past the end.
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn byte(&mut self) -> Option<u8> {
        let (&b, rest) = self.data.split_first()?;
        self.data = rest;
        Some(b)
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        if self.data.len() < 4 {
            return Err(invalid("truncated data"));
        }
        let (n, rest) = self.data.split_at(4);
        self.data = rest;
        Ok(u32::from_be_bytes(n.try_into().expect("4 bytes")))
    }

    pub fn string(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u32()? as usize;
        if self.data.len() < len {
            return Err(invalid("truncated data"));
        }
        let (s, rest) = self.data.split_at(len);
        self.data = rest;
        Ok(s)
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        // SigningKey zeroizes itself (the `zeroize` feature); the comment is
        // just tidy.
        self.comment.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated with `ssh-keygen -t ed25519 -C test@stash -N ''` and
    // `-N 'correct horse'`, for these tests only.
    const PLAIN: &str = include_str!("../tests/data/ed25519");
    const PLAIN_PUB: &str = include_str!("../tests/data/ed25519.pub");
    const ENCRYPTED: &str = include_str!("../tests/data/ed25519-encrypted");

    #[test]
    fn reads_ssh_keygen_files() {
        let pair = KeyPair::from_openssh(PLAIN, None).unwrap();
        assert_eq!(pair.public_line(), PLAIN_PUB.trim());
        assert_eq!(pair.comment, "test@stash");
    }

    #[test]
    fn reads_passphrase_protected_files() {
        assert!(matches!(
            KeyPair::from_openssh(ENCRYPTED, None),
            Err(Error::SshPassphrase)
        ));
        assert!(matches!(
            KeyPair::from_openssh(ENCRYPTED, Some(b"wrong")),
            Err(Error::SshPassphrase)
        ));
        let pair = KeyPair::from_openssh(ENCRYPTED, Some(b"correct horse")).unwrap();
        let plain = KeyPair::from_openssh(PLAIN, None).unwrap();
        assert_ne!(pair.public(), plain.public(), "a different test key");
        assert!(pair.public_line().starts_with("ssh-ed25519 AAAA"));
    }

    #[test]
    fn round_trips_its_own_format() {
        let pair = KeyPair::generate("me@laptop").unwrap();
        let again = KeyPair::from_openssh(&pair.to_openssh(), None).unwrap();
        assert_eq!(again.public(), pair.public());
        assert_eq!(again.comment, "me@laptop");
        assert_eq!(again.to_openssh().as_str(), pair.to_openssh().as_str());
    }

    #[test]
    fn signatures_verify() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let pair = KeyPair::generate("").unwrap();
        let blob = pair.sign(b"hello");
        let mut r = Reader::new(&blob);
        assert_eq!(r.string().unwrap(), KEY_TYPE.as_bytes());
        let sig = Signature::from_slice(r.string().unwrap()).unwrap();
        let key = VerifyingKey::from_bytes(&pair.public()).unwrap();
        assert!(key.verify(b"hello", &sig).is_ok());
        assert!(key.verify(b"hellO", &sig).is_err());
    }

    #[test]
    fn fingerprints_match_ssh_keygen() {
        // `ssh-keygen -lf tests/data/ed25519.pub`
        let pair = KeyPair::from_openssh(PLAIN, None).unwrap();
        assert_eq!(
            pair.fingerprint(),
            include_str!("../tests/data/ed25519.fingerprint").trim()
        );
        assert_eq!(blob_from_line(PLAIN_PUB).unwrap(), pair.public_blob());
    }

    #[test]
    fn refuses_other_formats_clearly() {
        let msg = |t: &str| KeyPair::from_openssh(t, None).err().unwrap().to_string();
        assert!(
            msg("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----")
                .contains("older key format")
        );
        assert!(msg(PLAIN_PUB).contains("public key"));
        assert!(msg("hello").contains("not an OpenSSH"));
        let truncated = &PLAIN[..PLAIN.len() / 2];
        assert!(KeyPair::from_openssh(truncated, None).is_err());
    }

    #[test]
    fn reads_what_a_signature_is_for() {
        let mut sshsig = SSHSIG_MAGIC.to_vec();
        put_string(&mut sshsig, b"git");
        assert_eq!(
            SignPurpose::of(&sshsig),
            SignPurpose::File {
                namespace: "git".into()
            }
        );

        let mut login = Vec::new();
        put_string(&mut login, b"session-id");
        login.push(50);
        put_string(&mut login, b"git");
        put_string(&mut login, b"ssh-connection");
        put_string(&mut login, b"publickey");
        assert_eq!(
            SignPurpose::of(&login),
            SignPurpose::Login { user: "git".into() }
        );

        assert_eq!(
            SignPurpose::of(b"\x00\x00\x00\x09garbage"),
            SignPurpose::Unknown
        );
        assert_eq!(SignPurpose::of(b""), SignPurpose::Unknown);
    }
}
