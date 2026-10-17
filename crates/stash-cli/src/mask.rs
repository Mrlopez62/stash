//! Hide secret values in a child process's output.
//!
//! Output is streamed, not buffered: bytes are written as soon as they can't
//! be the start of a secret, so prompts and progress bars still appear
//! promptly. Only a possible partial match at the end of a read is held back
//! until the next read shows whether it's a secret.
//!
//! This is best-effort. A program that prints a secret in a different form
//! (base64, split across lines, URL-encoded) is not masked.

use std::io::{self, ErrorKind, Read, Write};

use zeroize::Zeroizing;

pub const CONCEALED: &[u8] = b"<concealed by stash>";

/// Values shorter than this aren't masked. Hiding every `1` or `true` in the
/// output would make it unreadable while protecting nothing.
pub const MIN_MASK_LEN: usize = 4;

pub struct Masker {
    /// Longest first, so the longest overlapping secret wins.
    secrets: Vec<Zeroizing<Vec<u8>>>,
}

impl Masker {
    pub fn new<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let mut secrets: Vec<Zeroizing<Vec<u8>>> = values
            .into_iter()
            .filter(|v| v.len() >= MIN_MASK_LEN)
            .map(|v| Zeroizing::new(v.to_vec()))
            .collect();
        secrets.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        secrets.dedup();
        Self { secrets }
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Copy `reader` to `writer` until EOF, replacing secrets with [`CONCEALED`].
    pub fn pump(&self, mut reader: impl Read, mut writer: impl Write) -> io::Result<()> {
        let mut buf = Zeroizing::new([0u8; 8192]);
        let mut pending = Zeroizing::new(Vec::new());
        loop {
            let n = match reader.read(buf.as_mut()) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            pending.extend_from_slice(&buf[..n]);
            let (out, held) = self.process(&pending, false);
            writer.write_all(&out)?;
            writer.flush()?;
            *pending = held;
        }
        let (out, _) = self.process(&pending, true);
        writer.write_all(&out)?;
        writer.flush()
    }

    /// Mask everything that can be decided now. Returns the output and the
    /// bytes held back because they might begin a secret (empty at EOF).
    fn process(&self, data: &[u8], eof: bool) -> (Vec<u8>, Vec<u8>) {
        let mut out = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            let rest = &data[i..];
            // Wait for more input while a longer secret could still match
            // here, even if a shorter one already does.
            if !eof
                && self
                    .secrets
                    .iter()
                    .any(|s| s.len() > rest.len() && s.starts_with(rest))
            {
                break;
            }
            if let Some(secret) = self.secrets.iter().find(|s| rest.starts_with(s)) {
                out.extend_from_slice(CONCEALED);
                i += secret.len();
                continue;
            }
            out.push(data[i]);
            i += 1;
        }
        (out, data[i..].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds input in fixed-size chunks to exercise matches across reads.
    struct Chunked<'a>(&'a [u8], usize);

    impl Read for Chunked<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.1.min(self.0.len()).min(buf.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    fn mask(secrets: &[&str], input: &str, chunk: usize) -> String {
        let masker = Masker::new(secrets.iter().map(|s| s.as_bytes()));
        let mut out = Vec::new();
        masker
            .pump(Chunked(input.as_bytes(), chunk), &mut out)
            .unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn masks_secrets_at_any_chunk_size() {
        let input = "token=ghp_abc123 again ghp_abc123!";
        let expected = "token=<concealed by stash> again <concealed by stash>!";
        for chunk in [1, 2, 3, 7, 8192] {
            assert_eq!(
                mask(&["ghp_abc123"], input, chunk),
                expected,
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn prefers_the_longest_overlapping_secret() {
        assert_eq!(
            mask(&["abcd", "abcdefgh"], "xabcdefghx abcdx", 3),
            "x<concealed by stash>x <concealed by stash>x"
        );
    }

    #[test]
    fn flushes_partial_matches_that_turn_out_not_to_be_secrets() {
        assert_eq!(mask(&["secretvalue"], "secre", 2), "secre");
        assert_eq!(mask(&["secretvalue"], "secret-ish", 4), "secret-ish");
    }

    #[test]
    fn ignores_very_short_values() {
        let masker = Masker::new([b"1".as_slice(), b"abc".as_slice()]);
        assert!(masker.is_empty());
        assert_eq!(mask(&["1"], "1 + 1", 1), "1 + 1");
    }

    #[test]
    fn writes_unrelated_output_without_holding_it_back() {
        let masker = Masker::new([b"zzzz".as_slice()]);
        let (out, held) = masker.process(b"Password: ", false);
        assert_eq!(out, b"Password: ");
        assert!(held.is_empty());
    }
}
