//! A small `.env` parser: `KEY=value` lines, with `#` comments, an optional
//! `export ` prefix, and single- or double-quoted values.

use anyhow::{Result, bail};

pub fn parse(contents: &str) -> Result<Vec<(String, String)>> {
    let mut vars = Vec::new();
    for (index, raw) in contents.lines().enumerate() {
        let line_no = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            bail!("line {line_no}: expected KEY=value");
        };
        let key = key.trim();
        if !is_valid_key(key) {
            bail!("line {line_no}: `{key}` is not a valid variable name");
        }
        let value = parse_value(value.trim_start())
            .map_err(|why| anyhow::anyhow!("line {line_no}: {why}"))?;
        vars.push((key.to_owned(), value));
    }
    Ok(vars)
}

fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn parse_value(value: &str) -> Result<String, &'static str> {
    if let Some(rest) = value.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = rest.chars();
        loop {
            match chars.next() {
                None => return Err("unterminated double quote"),
                Some('"') => break,
                Some('\\') => match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('r') => out.push('\r'),
                    Some(c @ ('"' | '\\' | '$')) => out.push(c),
                    Some(c) => {
                        out.push('\\');
                        out.push(c);
                    }
                    None => return Err("unterminated double quote"),
                },
                Some(c) => out.push(c),
            }
        }
        expect_end(chars.as_str())?;
        Ok(out)
    } else if let Some(rest) = value.strip_prefix('\'') {
        let Some((inner, after)) = rest.split_once('\'') else {
            return Err("unterminated single quote");
        };
        expect_end(after)?;
        Ok(inner.to_owned())
    } else {
        // Unquoted: an inline comment needs whitespace before the `#`.
        let end = value
            .char_indices()
            .find(|&(i, c)| c == '#' && value[..i].ends_with(char::is_whitespace))
            .map_or(value.len(), |(i, _)| i);
        Ok(value[..end].trim_end().to_owned())
    }
}

fn expect_end(rest: &str) -> Result<(), &'static str> {
    let rest = rest.trim();
    if rest.is_empty() || rest.starts_with('#') {
        Ok(())
    } else {
        Err("unexpected text after closing quote")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kv(contents: &str) -> Vec<(String, String)> {
        parse(contents).unwrap()
    }

    #[test]
    fn parses_common_forms() {
        let vars = kv(r#"
# comment
GITHUB_TOKEN=stash://github/token
export OPENAI_API_KEY = stash://openai/api-key
PLAIN=hello world   # trailing comment
URL=https://x.test/#anchor
DQ="a \"quoted\"\nvalue" # ok
SQ='literal \n $HOME'
EMPTY=
"#);
        let get = |k: &str| vars.iter().find(|(key, _)| key == k).unwrap().1.as_str();
        assert_eq!(get("GITHUB_TOKEN"), "stash://github/token");
        assert_eq!(get("OPENAI_API_KEY"), "stash://openai/api-key");
        assert_eq!(get("PLAIN"), "hello world");
        assert_eq!(get("URL"), "https://x.test/#anchor");
        assert_eq!(get("DQ"), "a \"quoted\"\nvalue");
        assert_eq!(get("SQ"), "literal \\n $HOME");
        assert_eq!(get("EMPTY"), "");
    }

    #[test]
    fn reports_line_numbers_for_errors() {
        for (input, msg) in [
            ("OK=1\nnope", "line 2: expected KEY=value"),
            ("1BAD=x", "not a valid variable name"),
            ("A=\"open", "unterminated double quote"),
            ("A='open", "unterminated single quote"),
            ("A=\"x\" junk", "unexpected text"),
        ] {
            let err = parse(input).unwrap_err().to_string();
            assert!(err.contains(msg), "{input:?}: {err}");
        }
    }
}
