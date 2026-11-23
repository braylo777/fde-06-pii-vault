//! Hand-written PII detectors (no regex engine) with validity checks to cut false positives.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Entity {
    pub kind: String,
    pub start: usize, // byte offsets into the text
    pub end: usize,
    pub value: String,
}

pub fn luhn(d: &str) -> bool {
    let digits: Vec<u32> = d.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| {
            if i % 2 == 1 {
                let y = x * 2;
                if y > 9 {
                    y - 9
                } else {
                    y
                }
            } else {
                x
            }
        })
        .sum();
    sum % 10 == 0
}

pub fn iban_ok(s: &str) -> bool {
    let s: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if s.len() < 15
        || s.len() > 34
        || !s[..2].chars().all(|c| c.is_ascii_alphabetic())
        || !s[2..4].chars().all(|c| c.is_ascii_digit())
    {
        return false;
    }
    let rearranged = format!("{}{}", &s[4..], &s[..4]);
    let mut rem: u32 = 0;
    for c in rearranged.chars() {
        let v = match c {
            '0'..='9' => c as u32 - '0' as u32,
            'A'..='Z' => c as u32 - 'A' as u32 + 10,
            _ => return false,
        };
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    rem == 1
}

pub fn ssn_ok(s: &str) -> bool {
    let d: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if d.len() != 9 {
        return false;
    }
    let (a, g, n) = (&d[..3], &d[3..5], &d[5..]);
    a != "000" && a != "666" && !a.starts_with('9') && g != "00" && n != "0000"
}

fn is_email_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "._%+-".contains(c)
}

fn push(out: &mut Vec<Entity>, kind: &str, text: &str, s: usize, e: usize) {
    if out.iter().any(|x| s < x.end && e > x.start) {
        return; // first detector to claim a span wins (ordered most specific first)
    }
    out.push(Entity {
        kind: kind.into(),
        start: s,
        end: e,
        value: text[s..e].to_string(),
    });
}

/// Spans of digits allowing single spaces / dashes / dots / parens between them.
fn digit_runs(text: &str) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let mut runs = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit()
            || (b[i] == b'+' && i + 1 < b.len() && b[i + 1].is_ascii_digit())
            || (b[i] == b'(' && i + 1 < b.len() && b[i + 1].is_ascii_digit())
        {
            let s = i;
            let mut e = i + 1;
            let mut j = i + 1;
            while j < b.len() {
                if b[j].is_ascii_digit() || (b[j] == b')' && b[s..j].contains(&b'(') && !b[s..j].contains(&b')')) {
                    j += 1;
                    e = j;
                } else if matches!(b[j], b' ' | b'-' | b'.')
                    && j + 1 < b.len()
                    && (b[j + 1].is_ascii_digit() || b[j + 1] == b'(')
                {
                    j += 1;
                } else if b[j] == b'(' && j + 1 < b.len() && b[j + 1].is_ascii_digit() {
                    j += 1; // area code in parentheses after a separator
                } else {
                    break;
                }
            }
            let before_ok = s == 0 || !b[s - 1].is_ascii_alphanumeric();
            let after_ok = e >= b.len() || !b[e].is_ascii_alphanumeric();
            if before_ok && after_ok {
                runs.push((s, e));
            }
            i = e.max(i + 1);
        } else {
            i += 1;
        }
    }
    runs
}

pub fn detect(text: &str, first_names: &[String]) -> Vec<Entity> {
    let mut out: Vec<Entity> = Vec::new();
    let b = text.as_bytes();
    // Emails
    for (at, _) in text.match_indices('@') {
        let mut s = at;
        while s > 0 && is_email_char(b[s - 1] as char) {
            s -= 1;
        }
        let mut e = at + 1;
        while e < b.len() && (b[e].is_ascii_alphanumeric() || b[e] == b'.' || b[e] == b'-') {
            e += 1;
        }
        while e > at + 1 && b[e - 1] == b'.' {
            e -= 1;
        }
        let domain = &text[at + 1..e];
        if s < at
            && domain.contains('.')
            && domain
                .rsplit('.')
                .next()
                .map(|t| t.len() >= 2)
                .unwrap_or(false)
        {
            push(&mut out, "EMAIL", text, s, e);
        }
    }
    // IBANs: 2 letters + 2 digits then alnum groups
    let mut i = 0;
    while i + 4 <= b.len() {
        if b[i].is_ascii_uppercase()
            && b[i + 1].is_ascii_uppercase()
            && b[i + 2].is_ascii_digit()
            && b[i + 3].is_ascii_digit()
            && (i == 0 || !b[i - 1].is_ascii_alphanumeric())
        {
            let mut e = i + 4;
            while e < b.len()
                && (b[e].is_ascii_alphanumeric()
                    || (b[e] == b' ' && e + 1 < b.len() && b[e + 1].is_ascii_alphanumeric()))
            {
                e += 1;
            }
            // shrink from the right until it validates (trailing words are common)
            let mut end = e;
            while end > i + 15 && !iban_ok(&text[i..end]) {
                end -= 1;
            }
            while end > i && b[end - 1] == b' ' {
                end -= 1;
            }
            if iban_ok(&text[i..end]) {
                push(&mut out, "IBAN", text, i, end.min(e));
                i = end;
                continue;
            }
        }
        i += 1;
    }
    // Digit-based: cards, SSNs, IPs, phones
    for (s, e) in digit_runs(text) {
        let span = &text[s..e];
        let digits: String = span.chars().filter(|c| c.is_ascii_digit()).collect();
        let dots = span.matches('.').count();
        if dots == 3
            && span
                .split('.')
                .all(|p| p.parse::<u8>().is_ok() && !p.is_empty())
        {
            push(&mut out, "IPV4", text, s, e);
        } else if luhn(&digits) && (13..=19).contains(&digits.len()) {
            push(&mut out, "CARD", text, s, e);
        } else if digits.len() == 9
            && span.len() == 11
            && span.as_bytes()[3] == b'-'
            && span.as_bytes()[6] == b'-'
            && ssn_ok(span)
        {
            push(&mut out, "SSN", text, s, e);
        } else if (10..=15).contains(&digits.len())
            && dots == 0
            && (span.starts_with('+') || span.contains(['-', ' ', '(']) || digits.len() == 10)
        {
            push(&mut out, "PHONE", text, s, e);
        }
    }
    // Person names: title + capitalized word(s), or a known first name + capitalized surname.
    let words: Vec<(usize, &str)> = text
        .split_inclusive(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == ':')
        .scan(0, |pos, w| {
            let s = *pos;
            *pos += w.len();
            Some((
                s,
                w.trim_end_matches(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == ':'),
            ))
        })
        .filter(|(_, w)| !w.is_empty())
        .collect();
    let cap = |w: &str| {
        w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
            && w.chars()
                .skip(1)
                .all(|c| c.is_lowercase() || c == '\'' || c == '-')
    };
    let titles = [
        "Mr.", "Mrs.", "Ms.", "Dr.", "Mr", "Mrs", "Ms", "Dr", "Prof.",
    ];
    for (k, &(s, w)) in words.iter().enumerate() {
        let next = words.get(k + 1);
        let clean = w.trim_end_matches('.');
        let is_title = titles.contains(&w);
        let is_first = first_names.iter().any(|n| n.eq_ignore_ascii_case(clean)) && cap(clean);
        if (is_title || is_first)
            && next
                .map(|(_, n)| cap(n.trim_end_matches('.')))
                .unwrap_or(false)
        {
            let (ns, nw) = next.unwrap();
            let mut e = ns + nw.trim_end_matches('.').len();
            // include a second surname word, e.g. "Dr. Ana de Souza" stops at lowercase "de"
            if let Some((ns2, nw2)) = words.get(k + 2) {
                if is_title && cap(nw2.trim_end_matches('.')) {
                    e = ns2 + nw2.trim_end_matches('.').len();
                }
            }
            let start = if is_title { s } else { s };
            push(&mut out, "PERSON", text, start, e);
        }
    }
    out.sort_by_key(|e| e.start);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn kinds(t: &str) -> Vec<String> {
        detect(t, &["maria".into()])
            .into_iter()
            .map(|e| format!("{}:{}", e.kind, e.value))
            .collect()
    }
    #[test]
    fn validators() {
        assert!(luhn("4111 1111 1111 1111"));
        assert!(!luhn("4111 1111 1111 1112"));
        assert!(iban_ok("GB82 WEST 1234 5698 7654 32"));
        assert!(!iban_ok("GB82 WEST 1234 5698 7654 33"));
        assert!(ssn_ok("123-45-6789"));
        assert!(!ssn_ok("666-45-6789") && !ssn_ok("123-00-6789"));
    }
    #[test]
    fn finds_each_kind() {
        let k = kinds("Mail jo.doe+x@acme.co.uk, card 4111-1111-1111-1111, SSN 123-45-6789, call +1 (415) 555-0132, ip 10.0.0.12, IBAN GB82 WEST 1234 5698 7654 32 today. Maria Lopez agreed; Dr. Chen too.");
        assert!(k.contains(&"EMAIL:jo.doe+x@acme.co.uk".to_string()));
        assert!(k.contains(&"CARD:4111-1111-1111-1111".to_string()));
        assert!(k.contains(&"SSN:123-45-6789".to_string()));
        assert!(k.contains(&"PHONE:+1 (415) 555-0132".to_string()));
        assert!(k.contains(&"IPV4:10.0.0.12".to_string()));
        assert!(k.contains(&"IBAN:GB82 WEST 1234 5698 7654 32".to_string()));
        assert!(k.contains(&"PERSON:Maria Lopez".to_string()));
        assert!(k.contains(&"PERSON:Dr. Chen".to_string()));
    }
    #[test]
    fn no_false_positives_on_plain_numbers() {
        assert!(kinds(
            "Order 12345 shipped on 2024-03-01 for 1,250.00 USD, invoice 4111111111111112."
        )
        .is_empty());
    }
}
