//! Which logins may fill on which web pages: the rule that stops phishing.
//!
//! A login fills only on a page whose *site* matches one of the login's
//! websites:
//!
//! - **Sites are registrable domains** (eTLD+1, from the Public Suffix
//!   List): `www.github.com` and `gist.github.com` are both `github.com`,
//!   but `github.com.evil.io` is `evil.io`, and `alice.github.io` and
//!   `bob.github.io` are different sites.
//! - **Hosts are compared in their ASCII (punycode) form**, which the URL
//!   parser produces, so a look-alike Unicode domain never equals the real
//!   one.
//! - **Only https pages fill**, except local development hosts
//!   (`localhost`, `*.localhost`, loopback addresses), which must match host
//!   *and* port exactly.
//! - **IP addresses and single-label hosts** match only exactly.

use url::{Host, Url};

/// Why a page can't be filled at all.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    NotAWebPage,
    NotHttps,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refusal::NotAWebPage => "stash only fills web pages",
            Refusal::NotHttps => "stash only fills pages loaded over https",
        })
    }
}

/// What a page or a website is, for matching.
#[derive(Debug, PartialEq, Eq, Clone)]
enum Site {
    /// A registrable domain: matches any host under it.
    Domain(String),
    /// Matches only this exact host and port.
    Exact(String, Option<u16>),
}

fn is_local(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(d) => *d == "localhost" || d.ends_with(".localhost"),
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => ip.is_loopback(),
    }
}

fn site_of(url: &Url) -> Option<Site> {
    let host = url.host()?;
    let port = url.port_or_known_default();
    if is_local(&host) {
        return Some(Site::Exact(url.host_str()?.to_owned(), port));
    }
    match host {
        Host::Domain(d) => {
            let d = d.trim_end_matches('.');
            // A public suffix itself (`com`, `co.uk`, `github.io`) is
            // nobody's site.
            if psl::suffix(d.as_bytes())
                .is_some_and(|s| s.is_known() && s.as_bytes() == d.as_bytes())
            {
                return None;
            }
            match psl::domain_str(d) {
                // Only a real registrable domain (`a.b`, not `intranet`).
                Some(registrable) if registrable.contains('.') => {
                    Some(Site::Domain(registrable.to_owned()))
                }
                _ => Some(Site::Exact(d.to_owned(), port)),
            }
        }
        Host::Ipv4(_) | Host::Ipv6(_) => Some(Site::Exact(url.host_str()?.to_owned(), port)),
    }
}

/// The page, if stash may fill it at all.
fn page(page_url: &str) -> Result<(Url, Site), Refusal> {
    let url = Url::parse(page_url).map_err(|_| Refusal::NotAWebPage)?;
    let host = url.host().ok_or(Refusal::NotAWebPage)?;
    match url.scheme() {
        "https" => {}
        "http" if is_local(&host) => {}
        "http" => return Err(Refusal::NotHttps),
        _ => return Err(Refusal::NotAWebPage),
    }
    let site = site_of(&url).ok_or(Refusal::NotAWebPage)?;
    Ok((url, site))
}

/// A login's website as saved: `https://github.com/login`, or just
/// `github.com`.
fn website(saved: &str) -> Option<Site> {
    let saved = saved.trim();
    let url = match Url::parse(saved) {
        Ok(u) if matches!(u.scheme(), "http" | "https") => u,
        // "github.com" parses as a relative URL error, or as a scheme
        // ("localhost:3000" → scheme "localhost"); both mean "no scheme".
        _ => Url::parse(&format!("https://{saved}")).ok()?,
    };
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    // A saved http://localhost:3000 keeps its port; anything else saved
    // as http still only fills over https (checked on the page side).
    site_of(&url)
}

/// Can a login saved for `saved_website` fill on `page_url`?
pub fn may_fill(page_url: &str, saved_website: &str) -> Result<bool, Refusal> {
    let (_, page_site) = page(page_url)?;
    Ok(website(saved_website).is_some_and(|w| w == page_site))
}

/// Check the page alone (before looking at any login).
pub fn check_page(page_url: &str) -> Result<(), Refusal> {
    page(page_url).map(|_| ())
}

/// The host to show the user: `github.com`, `localhost:3000`.
pub fn display_host(page_url: &str) -> Option<String> {
    let url = Url::parse(page_url).ok()?;
    let host = url.host_str()?.trim_end_matches('.').to_owned();
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fills(page: &str, saved: &str) -> bool {
        may_fill(page, saved).unwrap_or(false)
    }

    #[test]
    fn same_site_fills() {
        assert!(fills("https://github.com/login", "https://github.com"));
        assert!(fills("https://github.com/login", "github.com"));
        assert!(fills("https://www.github.com/", "https://github.com/login"));
        assert!(fills("https://gist.github.com/", "github.com"));
        assert!(fills("https://GitHub.com./login", "github.com"));
        assert!(fills(
            "https://accounts.example.co.uk/",
            "https://example.co.uk"
        ));
        // Saved as http, filled on the https page.
        assert!(fills("https://example.com/", "http://example.com"));
    }

    #[test]
    fn look_alikes_never_fill() {
        assert!(!fills("https://github.com.evil.io/login", "github.com"));
        assert!(!fills("https://evil-github.com/", "github.com"));
        assert!(!fills("https://githu8.com/", "github.com"));
        assert!(!fills("https://github.co/", "github.com"));
        // Cyrillic "і" (U+0456): the browser shows punycode-different hosts.
        assert!(!fills("https://gіthub.com/", "github.com"));
        assert!(!fills("https://xn--gthub-n4a.com/", "github.com"));
        // The user-info trick: the host here is evil.io.
        assert!(!fills("https://github.com@evil.io/", "github.com"));
        // Other users' sites on shared hosting.
        assert!(!fills("https://bob.github.io/", "https://alice.github.io"));
        assert!(!fills("https://evil.co.uk/", "example.co.uk"));
    }

    #[test]
    fn unicode_websites_match_their_punycode_pages() {
        assert!(fills("https://xn--bcher-kva.de/", "https://bücher.de"));
        assert!(fills("https://bücher.de/", "xn--bcher-kva.de"));
    }

    #[test]
    fn only_https_except_local_development() {
        assert_eq!(
            may_fill("http://github.com/", "github.com"),
            Err(Refusal::NotHttps)
        );
        assert_eq!(
            may_fill("file:///etc/passwd", "github.com"),
            Err(Refusal::NotAWebPage)
        );
        assert_eq!(
            may_fill("chrome://settings", "x"),
            Err(Refusal::NotAWebPage)
        );
        assert_eq!(may_fill("not a url", "x"), Err(Refusal::NotAWebPage));
        assert!(fills(
            "http://localhost:3000/login",
            "http://localhost:3000"
        ));
        assert!(fills("http://127.0.0.1:8080/", "127.0.0.1:8080"));
        assert!(fills(
            "http://app.localhost:5173/",
            "http://app.localhost:5173"
        ));
    }

    #[test]
    fn local_hosts_and_ips_match_exactly() {
        assert!(!fills("http://localhost:3000/", "http://localhost:8080"));
        assert!(!fills("http://localhost:3000/", "github.com"));
        assert!(!fills("https://10.0.0.2/", "https://10.0.0.1"));
        assert!(fills("https://10.0.0.1/admin", "https://10.0.0.1"));
        assert!(!fills("https://10.0.0.1:8443/", "https://10.0.0.1"));
        assert!(fills("https://intranet/", "https://intranet"));
        assert!(!fills("https://wiki.intranet/", "https://intranet"));
    }

    #[test]
    fn junk_websites_never_match() {
        assert!(!fills("https://github.com/", ""));
        assert!(!fills("https://github.com/", "ftp://github.com"));
        assert!(!fills("https://github.com/", "javascript:alert(1)"));
        assert!(!fills("https://com/", "com"));
    }

    #[test]
    fn shows_hosts_plainly() {
        assert_eq!(
            display_host("https://github.com./login").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            display_host("http://localhost:3000/").as_deref(),
            Some("localhost:3000")
        );
        assert_eq!(
            display_host("https://xn--bcher-kva.de/").as_deref(),
            Some("xn--bcher-kva.de")
        );
    }
}
