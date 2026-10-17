//! Random password generation.
//!
//! Characters are drawn uniformly (rejection sampling, so no modulo bias)
//! from the OS random number generator. Passwords are redrawn until they
//! contain at least one character from every enabled class, which many sites
//! require.

use zeroize::Zeroizing;

use crate::Error;

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// No quotes, backslashes, or spaces, so passwords paste safely into shells
/// and config files.
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?";

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rules {
    pub length: usize,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            length: 24,
            uppercase: true,
            digits: true,
            symbols: true,
        }
    }
}

pub fn password(rules: Rules) -> Result<Zeroizing<String>, Error> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&rules.length) {
        return Err(Error::InvalidRules(format!(
            "length must be {MIN_LENGTH}–{MAX_LENGTH}"
        )));
    }
    let mut classes = vec![LOWERCASE];
    if rules.uppercase {
        classes.push(UPPERCASE);
    }
    if rules.digits {
        classes.push(DIGITS);
    }
    if rules.symbols {
        classes.push(SYMBOLS);
    }
    let alphabet: Vec<char> = classes.iter().flat_map(|c| c.chars()).collect();

    loop {
        let mut out = Zeroizing::new(String::with_capacity(rules.length));
        for _ in 0..rules.length {
            out.push(alphabet[uniform(alphabet.len())?]);
        }
        if classes
            .iter()
            .all(|class| out.chars().any(|c| class.contains(c)))
        {
            return Ok(out);
        }
    }
}

/// A uniform random index below `n`, without modulo bias.
fn uniform(n: usize) -> Result<usize, Error> {
    let n = n as u32;
    let limit = u32::MAX - u32::MAX % n;
    loop {
        let r = u32::from_le_bytes(crate::crypto::random_bytes()?);
        if r < limit {
            return Ok((r % n) as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length_and_classes() {
        for _ in 0..200 {
            let pw = password(Rules::default()).unwrap();
            assert_eq!(pw.chars().count(), 24);
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pw.chars().any(|c| c.is_ascii_digit()));
            assert!(pw.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn can_drop_classes() {
        let rules = Rules {
            length: 40,
            uppercase: false,
            digits: true,
            symbols: false,
        };
        let pw = password(rules).unwrap();
        assert!(
            pw.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn rejects_bad_lengths() {
        for length in [0, 7, 129] {
            let rules = Rules {
                length,
                ..Rules::default()
            };
            assert!(matches!(password(rules), Err(Error::InvalidRules(_))));
        }
    }

    #[test]
    fn passwords_differ() {
        let a = password(Rules::default()).unwrap();
        let b = password(Rules::default()).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn characters_are_roughly_uniform() {
        // 26 lowercase letters over 26_000 draws: each should land near 1000.
        let mut counts = [0u32; 26];
        for _ in 0..26_000 {
            counts[uniform(26).unwrap()] += 1;
        }
        assert!(
            counts.iter().all(|&c| (800..1200).contains(&c)),
            "{counts:?}"
        );
    }
}
