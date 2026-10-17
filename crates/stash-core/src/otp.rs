//! Time-based one-time passwords (TOTP, RFC 6238): the 6-digit codes that
//! authenticator apps show.
//!
//! A TOTP item's value is either an `otpauth://totp/...` URI (what the QR
//! code on a 2FA setup page contains) or a bare base32 secret.

use hmac::{EagerHash, Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

use crate::Error;

/// 80 bits, the shortest secret authenticator apps generate.
const MIN_SECRET_BYTES: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub digits: u32,
    pub period: u64,
    pub algorithm: Algorithm,
    /// From the URI, for display (e.g. "GitHub").
    pub issuer: Option<String>,
}

impl Totp {
    /// Parse an `otpauth://totp/...` URI or a bare base32 secret.
    pub fn parse(value: &str) -> Result<Self, Error> {
        let value = value.trim();
        let invalid = |why: &str| Error::InvalidOtp(why.to_owned());
        let mut totp = Totp {
            secret: Zeroizing::new(Vec::new()),
            digits: 6,
            period: 30,
            algorithm: Algorithm::Sha1,
            issuer: None,
        };

        let secret = if let Some(rest) = value.strip_prefix("otpauth://") {
            let (kind, rest) = rest
                .split_once('/')
                .ok_or_else(|| invalid("malformed otpauth URI"))?;
            if !kind.eq_ignore_ascii_case("totp") {
                return Err(invalid("only time-based (totp) codes are supported"));
            }
            let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
            let mut secret = None;
            for pair in query.split('&').filter(|p| !p.is_empty()) {
                let (key, raw) = pair.split_once('=').unwrap_or((pair, ""));
                let val = percent_decode(raw).ok_or_else(|| invalid("malformed URI encoding"))?;
                match key.to_ascii_lowercase().as_str() {
                    "secret" => secret = Some(Zeroizing::new(val)),
                    "issuer" => totp.issuer = Some(val),
                    "digits" => {
                        totp.digits = val
                            .parse()
                            .ok()
                            .filter(|d| (6..=8).contains(d))
                            .ok_or_else(|| invalid("digits must be 6, 7, or 8"))?;
                    }
                    "period" => {
                        totp.period = val
                            .parse()
                            .ok()
                            .filter(|p| (1..=300).contains(p))
                            .ok_or_else(|| invalid("period must be 1–300 seconds"))?;
                    }
                    "algorithm" => {
                        totp.algorithm = match val.to_ascii_uppercase().as_str() {
                            "SHA1" => Algorithm::Sha1,
                            "SHA256" => Algorithm::Sha256,
                            "SHA512" => Algorithm::Sha512,
                            _ => return Err(invalid("algorithm must be SHA1, SHA256, or SHA512")),
                        };
                    }
                    _ => {}
                }
            }
            secret.ok_or_else(|| invalid("the URI has no secret"))?
        } else {
            Zeroizing::new(value.to_owned())
        };

        totp.secret =
            base32_decode(&secret).ok_or_else(|| invalid("the secret isn't valid base32"))?;
        // RFC 4226 asks for at least 128 bits; authenticator apps accept 80.
        // Anything shorter is almost certainly a typo or the wrong paste.
        if totp.secret.len() < MIN_SECRET_BYTES {
            return Err(invalid(
                "the secret is too short (expected at least 16 base32 characters)",
            ));
        }
        Ok(totp)
    }

    /// The code for a Unix time, zero-padded to `digits`.
    pub fn code_at(&self, unix_secs: u64) -> String {
        let counter = (unix_secs / self.period).to_be_bytes();
        let mac = match self.algorithm {
            Algorithm::Sha1 => hmac::<sha1::Sha1>(&self.secret, &counter),
            Algorithm::Sha256 => hmac::<sha2::Sha256>(&self.secret, &counter),
            Algorithm::Sha512 => hmac::<sha2::Sha512>(&self.secret, &counter),
        };
        // Dynamic truncation (RFC 4226 §5.3).
        let offset = usize::from(mac[mac.len() - 1] & 0x0f);
        let binary = u32::from_be_bytes([
            mac[offset] & 0x7f,
            mac[offset + 1],
            mac[offset + 2],
            mac[offset + 3],
        ]);
        let code = binary % 10u32.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    /// Seconds until the code for `unix_secs` changes.
    pub fn remaining(&self, unix_secs: u64) -> u64 {
        self.period - unix_secs % self.period
    }
}

fn hmac<D: EagerHash>(key: &[u8], data: &[u8]) -> Zeroizing<Vec<u8>>
where
    Hmac<D>: KeyInit + Mac,
{
    let mut mac = <Hmac<D> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    Zeroizing::new(mac.finalize().into_bytes().to_vec())
}

/// RFC 4648 base32, case-insensitive, ignoring spaces, hyphens, and padding.
fn base32_decode(input: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8));
    let (mut buffer, mut bits) = (0u64, 0u32);
    for c in input.chars().filter(|c| !matches!(c, ' ' | '-' | '=')) {
        let value = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u64 - 'A' as u64,
            c @ '2'..='7' => c as u64 - '2' as u64 + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base32_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let (mut out, mut buffer, mut bits) = (String::new(), 0u32, 0u32);
        for &b in data {
            buffer = (buffer << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
        }
        out
    }

    /// RFC 6238 Appendix B.
    #[test]
    fn matches_the_rfc_6238_test_vectors() {
        let seeds = [
            ("SHA1", b"12345678901234567890".to_vec()),
            ("SHA256", b"12345678901234567890123456789012".to_vec()),
            (
                "SHA512",
                b"1234567890123456789012345678901234567890123456789012345678901234".to_vec(),
            ),
        ];
        let vectors: [(u64, [&str; 3]); 6] = [
            (59, ["94287082", "46119246", "90693936"]),
            (1_111_111_109, ["07081804", "68084774", "25091201"]),
            (1_111_111_111, ["14050471", "67062674", "99943326"]),
            (1_234_567_890, ["89005924", "91819424", "93441116"]),
            (2_000_000_000, ["69279037", "90698825", "38618901"]),
            (20_000_000_000, ["65353130", "77737706", "47863826"]),
        ];
        for (i, (alg, seed)) in seeds.iter().enumerate() {
            let uri = format!(
                "otpauth://totp/Test?secret={}&algorithm={alg}&digits=8&period=30",
                base32_encode(seed)
            );
            let totp = Totp::parse(&uri).unwrap();
            for (time, codes) in &vectors {
                assert_eq!(totp.code_at(*time), codes[i], "{alg} at {time}");
            }
        }
    }

    #[test]
    fn parses_typical_inputs() {
        let t = Totp::parse(
            "otpauth://totp/GitHub:me%40example.com?secret=jbsw y3dp-ehpk3pxp&issuer=GitHub",
        )
        .unwrap();
        assert_eq!((t.digits, t.period, t.algorithm), (6, 30, Algorithm::Sha1));
        assert_eq!(t.issuer.as_deref(), Some("GitHub"));
        assert_eq!(*t.secret, b"Hello!\xde\xad\xbe\xef");

        let bare = Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(bare.code_at(59).len(), 6);
        assert_eq!(bare.remaining(59), 1);
        assert_eq!(bare.remaining(60), 30);
    }

    #[test]
    fn rejects_bad_inputs() {
        for bad in [
            "",
            "not base32!",
            "not a secret",
            "JBSWY3DPEHPK3PX",
            "otpauth://hotp/X?secret=JBSWY3DP",
            "otpauth://totp/X?issuer=NoSecret",
            "otpauth://totp/X?secret=JBSWY3DP&digits=4",
            "otpauth://totp/X?secret=JBSWY3DP&period=0",
            "otpauth://totp/X?secret=JBSWY3DP&algorithm=MD5",
        ] {
            assert!(
                matches!(Totp::parse(bad), Err(Error::InvalidOtp(_))),
                "{bad:?}"
            );
        }
    }
}
