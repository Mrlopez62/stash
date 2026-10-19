//! Text from outside (an AI agent's command, a process name, a client's
//! self-chosen name) made safe to show in a Touch ID prompt or a log.

/// Invisible characters that change how text *looks* without being seen:
/// bidirectional overrides and isolates (which can make `curl evil.sh`
/// display reversed), zero-width spaces and joiners, the soft hyphen, the
/// byte-order mark, and Unicode "tag" characters.
fn is_invisible_format(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}'
        | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}'
        | '\u{FFF0}'..='\u{FFFB}'
        | '\u{E0000}'..='\u{E0FFF}')
}

/// Replace control characters with spaces, drop invisible formatting
/// characters, and cut to `max` characters (ending in `…`).
pub fn clean(s: &str, max: usize) -> String {
    let clean: String = s
        .chars()
        .filter(|&c| !is_invisible_format(c))
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if clean.chars().count() > max {
        let mut cut: String = clean.chars().take(max.saturating_sub(1)).collect();
        cut.push('…');
        cut
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_what_could_disguise_a_command() {
        assert_eq!(clean("a\nb\x1b[31m", 40), "a b [31m");
        assert_eq!(clean("abcdef", 4), "abc…");
        // "curl evil.sh" written backwards behind a right-to-left override.
        assert_eq!(
            clean("echo hi \u{202E}hs.live lruc", 40),
            "echo hi hs.live lruc"
        );
        assert_eq!(clean("g\u{200B}it\u{2066}hub\u{FEFF}", 40), "github");
        assert_eq!(clean("tag\u{E0041}\u{E0042}s", 40), "tags");
        // Ordinary text, including other scripts and emoji, is kept.
        assert_eq!(clean("café 東京 ✅", 40), "café 東京 ✅");
    }
}
