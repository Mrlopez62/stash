//! Secret references: `stash://<name>` stands in for a secret's value in
//! environment variables, `.env` files, and templates.

use crate::{Error, validate_name};

pub const SCHEME: &str = "stash://";

/// Parse a whole value as a reference: `stash://github/token` → `github/token`.
///
/// Returns `Ok(None)` when the value isn't a reference at all, and an error
/// when it uses the `stash://` scheme with an invalid name, so typos fail
/// loudly instead of passing the literal string through.
pub fn parse(value: &str) -> Result<Option<&str>, Error> {
    let Some(name) = value.trim().strip_prefix(SCHEME) else {
        return Ok(None);
    };
    validate_name(name)?;
    Ok(Some(name))
}

/// One `{{ stash://name }}` placeholder found in a template.
#[derive(Debug, PartialEq, Eq)]
pub struct Placeholder<'a> {
    /// Byte range of the whole `{{ ... }}`, braces included.
    pub span: std::ops::Range<usize>,
    pub name: &'a str,
}

/// Find every `{{ stash://name }}` in `template`. Whitespace inside the braces
/// is optional. `{{ ... }}` blocks that aren't stash references are left alone.
pub fn placeholders(template: &str) -> Result<Vec<Placeholder<'_>>, Error> {
    let mut found = Vec::new();
    let mut offset = 0;
    while let Some(open) = template[offset..].find("{{") {
        let start = offset + open;
        let Some(close) = template[start + 2..].find("}}") else {
            break;
        };
        let end = start + 2 + close + 2;
        let inner = &template[start + 2..end - 2];
        match parse(inner)? {
            Some(name) => {
                found.push(Placeholder {
                    span: start..end,
                    name,
                });
                offset = end;
            }
            None => offset = start + 2,
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_whole_value_references() {
        assert_eq!(parse("stash://github/token").unwrap(), Some("github/token"));
        assert_eq!(parse("  stash://a  ").unwrap(), Some("a"));
        assert_eq!(parse("ghp_literal").unwrap(), None);
        assert_eq!(parse("https://example.com").unwrap(), None);
    }

    #[test]
    fn rejects_malformed_references() {
        assert!(parse("stash://").is_err());
        assert!(parse("stash://bad name").is_err());
        assert!(parse("stash://../x").is_err());
    }

    #[test]
    fn finds_template_placeholders() {
        let t = "url: {{stash://db/url}}\nkey: {{ stash://api/key }}\nother: {{ not.ours }}";
        let found = placeholders(t).unwrap();
        let names: Vec<_> = found.iter().map(|p| p.name).collect();
        assert_eq!(names, ["db/url", "api/key"]);
        assert_eq!(&t[found[0].span.clone()], "{{stash://db/url}}");
        assert_eq!(&t[found[1].span.clone()], "{{ stash://api/key }}");
    }

    #[test]
    fn template_placeholder_errors_name_the_problem() {
        assert!(placeholders("{{ stash://bad name }}").is_err());
        assert!(
            placeholders("{{ unterminated stash://x")
                .unwrap()
                .is_empty()
        );
    }
}
