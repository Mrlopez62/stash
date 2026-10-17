use crate::Error;

pub const MAX_NAME_LEN: usize = 128;

/// Check that a secret name looks like `github/token`: path-like segments of
/// ASCII letters, digits, `.`, `_`, and `-`, separated by single slashes.
pub fn validate_name(name: &str) -> Result<(), Error> {
    let invalid = |why| Err(Error::InvalidName(name.to_owned(), why));
    if name.is_empty() {
        return invalid("name is empty");
    }
    if name.len() > MAX_NAME_LEN {
        return invalid("name is longer than 128 characters");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
    {
        return invalid("only letters, digits, `.`, `_`, `-`, and `/` are allowed");
    }
    for segment in name.split('/') {
        if segment.is_empty() {
            return invalid("leading, trailing, or repeated `/`");
        }
        if segment == "." || segment == ".." {
            return invalid("`.` and `..` segments are not allowed");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_typical_names() {
        for name in [
            "github",
            "github/token",
            "aws/prod/ACCESS_KEY",
            "my-app.v2/api_key",
        ] {
            assert!(validate_name(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn rejects_bad_names() {
        let long = "a".repeat(MAX_NAME_LEN + 1);
        for name in [
            "",
            "/a",
            "a/",
            "a//b",
            "a/../b",
            ".",
            "has space",
            "emoji🔑",
            &long,
        ] {
            assert!(validate_name(name).is_err(), "{name}");
        }
    }
}
