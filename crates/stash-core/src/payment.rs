//! Payment cards and bank accounts: validation and safe summaries.
//!
//! Everything here catches typos before they're saved (a mistyped card
//! number fails its Luhn checksum; a mistyped routing number fails its ABA
//! checksum; an IBAN fails mod-97). It never contacts anything.

use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Brand {
    Visa,
    Mastercard,
    Amex,
    Discover,
    Jcb,
    Diners,
    UnionPay,
    Other,
}

impl Brand {
    pub fn name(self) -> &'static str {
        match self {
            Brand::Visa => "Visa",
            Brand::Mastercard => "Mastercard",
            Brand::Amex => "American Express",
            Brand::Discover => "Discover",
            Brand::Jcb => "JCB",
            Brand::Diners => "Diners Club",
            Brand::UnionPay => "UnionPay",
            Brand::Other => "Card",
        }
    }

    /// Valid number lengths for this brand.
    fn lengths(self) -> &'static [usize] {
        match self {
            Brand::Visa => &[13, 16, 19],
            Brand::Mastercard => &[16],
            Brand::Amex => &[15],
            Brand::Discover | Brand::Jcb | Brand::UnionPay => &[16, 17, 18, 19],
            Brand::Diners => &[14, 15, 16, 17, 18, 19],
            Brand::Other => &[12, 13, 14, 15, 16, 17, 18, 19],
        }
    }

    pub fn cvv_length(self) -> usize {
        if self == Brand::Amex { 4 } else { 3 }
    }
}

/// Just the digits: "4242 4242-4242 4242" → "4242424242424242". Wiped
/// when dropped, since it's usually a whole card number.
pub fn digits(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len()));
    out.extend(s.chars().filter(char::is_ascii_digit));
    out
}

/// The brand, from the number's leading digits (IIN ranges).
pub fn brand(number: &str) -> Brand {
    let d = digits(number);
    let prefix = |n: usize| d.get(..n).and_then(|p| p.parse::<u32>().ok());
    match (prefix(1), prefix(2), prefix(3), prefix(4), prefix(6)) {
        (Some(4), ..) => Brand::Visa,
        (_, Some(34 | 37), ..) => Brand::Amex,
        (_, Some(51..=55), ..) | (.., Some(2221..=2720), _) => Brand::Mastercard,
        (.., Some(6011), _) | (_, _, Some(644..=649), ..) | (_, Some(65), ..) => Brand::Discover,
        (.., Some(3528..=3589), _) => Brand::Jcb,
        (_, Some(36 | 38 | 39), ..) | (_, _, Some(300..=305), ..) => Brand::Diners,
        (_, Some(62), ..) => Brand::UnionPay,
        _ => Brand::Other,
    }
}

/// The Luhn checksum every real card number passes.
pub fn luhn(number: &str) -> bool {
    let d = digits(number);
    if d.is_empty() {
        return false;
    }
    let sum: u32 = d
        .bytes()
        .rev()
        .enumerate()
        .map(|(i, b)| {
            let n = u32::from(b - b'0');
            if i % 2 == 1 {
                let doubled = n * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                n
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

pub fn validate_card_number(number: &str) -> Result<Brand, Error> {
    let invalid = |why: &str| Error::InvalidPayment(why.to_owned());
    if number
        .chars()
        .any(|c| !(c.is_ascii_digit() || c == ' ' || c == '-'))
    {
        return Err(invalid(
            "a card number has only digits (spaces and dashes are fine)",
        ));
    }
    let d = digits(number);
    let brand = brand(&d);
    if !brand.lengths().contains(&d.len()) {
        return Err(invalid(&format!(
            "a {} number has {} digits; this one has {}",
            brand.name(),
            describe_lengths(brand.lengths()),
            d.len()
        )));
    }
    if !luhn(&d) {
        return Err(invalid(
            "that card number has a typo (its checksum doesn't match)",
        ));
    }
    Ok(brand)
}

fn describe_lengths(lengths: &[usize]) -> String {
    match lengths {
        [one] => one.to_string(),
        [first, .., last] if last - first + 1 == lengths.len() => format!("{first}–{last}"),
        _ => lengths
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    }
}

/// "MM/YY" or "MM/YYYY" → (month, four-digit year).
pub fn parse_expiry(expiry: &str) -> Result<(u32, u32), Error> {
    let invalid = || Error::InvalidPayment("use MM/YY for the expiry date, like 08/27".into());
    let (m, y) = expiry.trim().split_once('/').ok_or_else(invalid)?;
    let month: u32 = m.trim().parse().map_err(|_| invalid())?;
    let year: u32 = y.trim().parse().map_err(|_| invalid())?;
    let year = match y.trim().len() {
        2 => 2000 + year,
        4 => year,
        _ => return Err(invalid()),
    };
    if !(1..=12).contains(&month) {
        return Err(invalid());
    }
    Ok((month, year))
}

/// The most years ahead a card can expire. Real cards last far less, so
/// anything beyond this is a typo. An expired card is fine to keep.
const MAX_YEARS_AHEAD: u32 = 20;

/// A real date for a card: parses, and isn't implausibly far away.
pub fn validate_expiry(expiry: &str) -> Result<(), Error> {
    let seconds_per_year = 31_556_952;
    let this_year = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| 1970 + (d.as_secs() / seconds_per_year) as u32);
    validate_expiry_in(expiry, this_year)
}

fn validate_expiry_in(expiry: &str, this_year: u32) -> Result<(), Error> {
    let (_, year) = parse_expiry(expiry)?;
    if year > this_year + MAX_YEARS_AHEAD {
        return Err(Error::InvalidPayment(format!(
            "check the expiry year: {year} is more than {MAX_YEARS_AHEAD} years away"
        )));
    }
    Ok(())
}

/// Normalize to "MM/YY".
pub fn format_expiry(month: u32, year: u32) -> String {
    format!("{month:02}/{:02}", year % 100)
}

pub fn validate_cvv(cvv: &str, brand: Brand) -> Result<(), Error> {
    let ok = cvv.chars().all(|c| c.is_ascii_digit()) && (3..=4).contains(&cvv.len());
    if !ok {
        return Err(Error::InvalidPayment(format!(
            "the security code is the {} digits on the {}",
            brand.cvv_length(),
            if brand == Brand::Amex {
                "front"
            } else {
                "back"
            }
        )));
    }
    Ok(())
}

/// The last four digits, for safe display ("•••• 4242").
pub fn last4(number: &str) -> String {
    // The last four digits, without making a copy of the whole number.
    let mut last: Vec<char> = number
        .chars()
        .rev()
        .filter(char::is_ascii_digit)
        .take(4)
        .collect();
    last.reverse();
    last.into_iter().collect()
}

/// US ABA routing numbers: 9 digits with a weighted checksum.
pub fn validate_routing(routing: &str) -> Result<(), Error> {
    let d: Vec<u32> = routing.chars().filter_map(|c| c.to_digit(10)).collect();
    let all_digits = routing.chars().all(|c| c.is_ascii_digit() || c == ' ');
    let sum =
        |d: &[u32]| 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8]);
    if !all_digits || d.len() != 9 || !sum(&d).is_multiple_of(10) {
        return Err(Error::InvalidPayment(
            "a routing number is 9 digits (this one doesn't check out; look for a typo)".into(),
        ));
    }
    Ok(())
}

/// International Bank Account Numbers: country code, check digits, mod-97.
pub fn validate_iban(iban: &str) -> Result<(), Error> {
    let compact: String = iban
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    let invalid = || Error::InvalidPayment("that IBAN doesn't check out; look for a typo".into());
    if !(15..=34).contains(&compact.len())
        || !compact.chars().all(|c| c.is_ascii_alphanumeric())
        || !compact[..2].chars().all(|c| c.is_ascii_alphabetic())
    {
        return Err(invalid());
    }
    let rearranged = format!("{}{}", &compact[4..], &compact[..4]);
    let mut remainder: u32 = 0;
    for c in rearranged.chars() {
        let value = c.to_digit(36).ok_or_else(invalid)?;
        for digit in value.to_string().chars() {
            remainder = (remainder * 10 + digit.to_digit(10).expect("digit")) % 97;
        }
    }
    if remainder != 1 {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_brands_and_checks_luhn() {
        // Standard test numbers from card networks' documentation.
        for (number, expected) in [
            ("4242 4242 4242 4242", Brand::Visa),
            ("5555-5555-5555-4444", Brand::Mastercard),
            ("2223003122003222", Brand::Mastercard),
            ("378282246310005", Brand::Amex),
            ("6011111111111117", Brand::Discover),
            ("3566002020360505", Brand::Jcb),
            ("30569309025904", Brand::Diners),
            ("6200000000000005", Brand::UnionPay),
        ] {
            assert_eq!(validate_card_number(number).unwrap(), expected, "{number}");
        }
    }

    #[test]
    fn rejects_typos_and_wrong_lengths() {
        assert!(
            validate_card_number("4242 4242 4242 4241").is_err(),
            "one digit off"
        );
        assert!(
            validate_card_number("37828224631000").is_err(),
            "Amex is 15 digits"
        );
        assert!(validate_card_number("4242-abcd").is_err());
        assert!(validate_card_number("").is_err());
        let msg = validate_card_number("4242424242424241")
            .unwrap_err()
            .to_string();
        assert!(msg.contains("typo"), "{msg}");
    }

    #[test]
    fn parses_expiry_dates() {
        assert_eq!(parse_expiry("08/27").unwrap(), (8, 2027));
        assert_eq!(parse_expiry(" 1 / 2031 ").unwrap(), (1, 2031));
        assert_eq!(format_expiry(1, 2031), "01/31");
        for bad in ["13/27", "00/27", "0827", "08/2", "aa/bb"] {
            assert!(parse_expiry(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn refuses_implausible_expiry_dates() {
        assert!(validate_expiry_in("18/89", 2026).is_err(), "month 18");
        assert!(validate_expiry_in("08/89", 2026).is_err(), "2089");
        assert!(validate_expiry_in("08/46", 2026).is_ok(), "20 years out");
        assert!(validate_expiry_in("08/47", 2026).is_err(), "21 years out");
        assert!(
            validate_expiry_in("08/20", 2026).is_ok(),
            "expired is allowed"
        );
    }

    #[test]
    fn checks_security_codes() {
        assert!(validate_cvv("123", Brand::Visa).is_ok());
        assert!(validate_cvv("1234", Brand::Amex).is_ok());
        assert!(validate_cvv("12", Brand::Visa).is_err());
        let amex = validate_cvv("x", Brand::Amex).unwrap_err().to_string();
        assert!(amex.contains("4 digits on the front"), "{amex}");
    }

    #[test]
    fn checks_routing_numbers_and_ibans() {
        assert!(validate_routing("021000021").is_ok()); // a well-known valid ABA number
        assert!(validate_routing("021000022").is_err());
        assert!(validate_routing("12345").is_err());
        assert!(validate_iban("GB82 WEST 1234 5698 7654 32").is_ok()); // the IBAN spec's example
        assert!(validate_iban("DE89370400440532013000").is_ok());
        assert!(validate_iban("GB82 WEST 1234 5698 7654 33").is_err());
        assert!(validate_iban("not an iban").is_err());
    }

    #[test]
    fn shows_only_the_last_four() {
        assert_eq!(last4("4242 4242 4242 4242"), "4242");
        assert_eq!(last4("12"), "12");
    }
}
