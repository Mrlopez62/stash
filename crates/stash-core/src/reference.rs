//! Secret references: `stash://<name>` stands in for an item's main value,
//! and `stash://<name>#<field>` for one field (`#username`, `#otp` for the
//! current 2FA code, ...), in environment variables, `.env` files, and
//! templates.

use std::fmt;

use crate::{Error, validate_name};

pub const SCHEME: &str = "stash://";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reference<'a> {
    pub name: &'a str,
    pub field: Option<&'a str>,
}

impl fmt::Display for Reference<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}{}", self.name)?;
        if let Some(field) = self.field {
            write!(f, "#{field}")?;
        }
        Ok(())
    }
}

impl Reference<'_> {
    /// `name` or `name#field`, for prompts and logs.
    pub fn describe(&self) -> String {
        match self.field {
            Some(field) => format!("{}#{field}", self.name),
            None => self.name.to_owned(),
        }
    }

    pub fn to_owned(&self) -> ReferenceBuf {
        ReferenceBuf {
            name: self.name.to_owned(),
            field: self.field.map(str::to_owned),
        }
    }
}

/// An owned [`Reference`], for holding onto after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceBuf {
    pub name: String,
    pub field: Option<String>,
}

impl ReferenceBuf {
    pub fn as_ref(&self) -> Reference<'_> {
        Reference {
            name: &self.name,
            field: self.field.as_deref(),
        }
    }

    pub fn describe(&self) -> String {
        self.as_ref().describe()
    }
}

/// Parse a whole value as a reference: `stash://github/token`, or
/// `stash://github#username`.
///
/// Returns `Ok(None)` when the value isn't a reference at all, and an error
/// when it uses the `stash://` scheme with an invalid name or field, so
/// typos fail loudly instead of passing the literal string through.
pub fn parse(value: &str) -> Result<Option<Reference<'_>>, Error> {
    let Some(rest) = value.trim().strip_prefix(SCHEME) else {
        return Ok(None);
    };
    let (name, field) = match rest.split_once('#') {
        Some((name, field)) => (name, Some(field)),
        None => (rest, None),
    };
    validate_name(name)?;
    if let Some(field) = field {
        let ok = !field.is_empty()
            && field.len() <= 64
            && field
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'));
        if !ok {
            return Err(Error::InvalidName(
                rest.to_owned(),
                "field names may use letters, digits, spaces, `-`, `_`, and `.`",
            ));
        }
    }
    Ok(Some(Reference { name, field }))
}

/// A bare name or `name#field` as typed on the command line (with or
/// without the `stash://` prefix).
pub fn parse_arg(arg: &str) -> Result<Reference<'_>, Error> {
    if arg.trim().starts_with(SCHEME) {
        return Ok(parse(arg)?.expect("has the scheme"));
    }
    let (name, field) = match arg.split_once('#') {
        Some((name, field)) => (name, Some(field)),
        None => (arg, None),
    };
    validate_name(name)?;
    if let Some(field) = field {
        // Reuse the full validation.
        parse(&format!("{SCHEME}{name}#{field}"))?;
    }
    Ok(Reference { name, field })
}

/// One `{{ stash://name }}` placeholder found in a template.
#[derive(Debug, PartialEq, Eq)]
pub struct Placeholder<'a> {
    /// Byte range of the whole `{{ ... }}`, braces included.
    pub span: std::ops::Range<usize>,
    pub reference: Reference<'a>,
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
            Some(reference) => {
                found.push(Placeholder {
                    span: start..end,
                    reference,
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
        let r = |name, field| Some(Reference { name, field });
        assert_eq!(
            parse("stash://github/token").unwrap(),
            r("github/token", None)
        );
        assert_eq!(parse("  stash://a  ").unwrap(), r("a", None));
        assert_eq!(
            parse("stash://github#username").unwrap(),
            r("github", Some("username"))
        );
        assert_eq!(
            parse("stash://github#one-time password").unwrap(),
            r("github", Some("one-time password"))
        );
        assert_eq!(
            parse_arg("github#otp").unwrap(),
            Reference {
                name: "github",
                field: Some("otp")
            }
        );
        assert_eq!(
            parse_arg("stash://a").unwrap(),
            Reference {
                name: "a",
                field: None
            }
        );
        assert_eq!(parse("ghp_literal").unwrap(), None);
        assert_eq!(parse("https://example.com").unwrap(), None);
    }

    #[test]
    fn rejects_malformed_references() {
        assert!(parse("stash://").is_err());
        assert!(parse("stash://bad name").is_err());
        assert!(parse("stash://../x").is_err());
        assert!(parse("stash://a#").is_err());
        assert!(parse("stash://a#b$c").is_err());
        assert!(parse_arg("a#b/c").is_err());
    }

    #[test]
    fn finds_template_placeholders() {
        let t = "url: {{stash://db/url}}\nkey: {{ stash://api/key }}\nother: {{ not.ours }}";
        let found = placeholders(t).unwrap();
        let names: Vec<_> = found.iter().map(|p| p.reference.name).collect();
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
