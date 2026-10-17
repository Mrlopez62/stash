//! Terminal output in the stash palette (see docs/brand). Color is used only
//! when stderr is a terminal and `NO_COLOR` is unset.

use std::io::{self, IsTerminal};

/// Success green, `#7DD3A8`.
const SUCCESS: &str = "\x1b[38;2;125;211;168m";
const RESET: &str = "\x1b[0m";

fn color_enabled() -> bool {
    io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

/// A `✓` status line on stderr. Shown only on a terminal, so it never ends up
/// in logs or piped output.
pub fn success(message: &str) {
    if !io::stderr().is_terminal() {
        return;
    }
    if color_enabled() {
        eprintln!("{SUCCESS}✓ {message}{RESET}");
    } else {
        eprintln!("✓ {message}");
    }
}
