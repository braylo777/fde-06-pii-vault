//! Deterministic PII tokens (keyed HMAC), plus masking of a whole text.

use crate::{detect, names, str_field};
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;

pub fn hmac_hex(key: &str, msg: &str, n: usize) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
    m.update(msg.as_bytes());
    m.finalize()
        .into_bytes()
        .iter()
        .take(n)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Normalize before hashing so "Jo@Acme.com" and "jo@acme.com" get the same token.
pub fn normalize(kind: &str, v: &str) -> String {
    match kind {
        "EMAIL" => v.trim().to_ascii_lowercase(),
        "CARD" | "SSN" | "PHONE" => v.chars().filter(|c| c.is_ascii_digit()).collect(),
        "IBAN" => v
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_uppercase(),
        _ => v.split_whitespace().collect::<Vec<_>>().join(" "),
    }
}

pub fn token_for(key: &str, kind: &str, value: &str) -> String {
    format!(
        "<<{kind}_{}>>",
        hmac_hex(key, &format!("{kind}|{}", normalize(kind, value)), 6)
    )
}

/// Replace every detected entity with its token. Returns masked text + vault (token → value).
pub fn mask(
    text: &str,
    key: &str,
    first_names: &[String],
) -> (String, Map<String, Value>, Vec<detect::Entity>) {
    let ents = detect::detect(text, first_names);
    let mut out = String::new();
    let mut vault = Map::new();
    let mut pos = 0;
    for e in &ents {
        out.push_str(&text[pos..e.start]);
        let t = token_for(key, &e.kind, &e.value);
        vault.insert(t.clone(), json!(e.value));
        out.push_str(&t);
        pos = e.end;
    }
    out.push_str(&text[pos..]);
    (out, vault, ents)
}

pub fn check_key(key: &str) -> Result<(), String> {
    if key.len() < 16 {
        return Err("tenant key must be at least 16 bytes".into());
    }
    Ok(())
}

pub fn tokenize_op(i: &Value) -> Result<Value, String> {
    let key = str_field(i, "tenant_key")?;
    check_key(key)?;
    let (masked, vault, ents) = mask(str_field(i, "text")?, key, &names(i));
    let counts = ents.iter().fold(Map::new(), |mut m, e| {
        let c = m.get(&e.kind).and_then(Value::as_u64).unwrap_or(0);
        m.insert(e.kind.clone(), json!(c + 1));
        m
    });
    Ok(json!({"masked": masked, "vault": vault, "counts": counts}))
}

#[cfg(test)]
mod tests {
    use super::*;
    const K: &str = "tenant-acme-key-0001";
    #[test]
    fn deterministic_and_normalized() {
        assert_eq!(
            token_for(K, "EMAIL", "Jo@Acme.com"),
            token_for(K, "EMAIL", "jo@acme.com")
        );
        assert_eq!(
            token_for(K, "CARD", "4111 1111 1111 1111"),
            token_for(K, "CARD", "4111-1111-1111-1111")
        );
    }
    #[test]
    fn different_tenants_different_tokens() {
        assert_ne!(
            token_for(K, "EMAIL", "a@b.co"),
            token_for("tenant-globex-key-01", "EMAIL", "a@b.co")
        );
    }
    #[test]
    fn same_value_same_token_in_text() {
        let (m, v, _) = mask("a@b.co wrote to c@d.co, then a@b.co again", K, &[]);
        assert_eq!(v.len(), 2);
        assert!(!m.contains('@'));
        let t = token_for(K, "EMAIL", "a@b.co");
        assert_eq!(m.matches(&t).count(), 2);
    }
    #[test]
    fn short_key_refused() {
        assert!(check_key("short").is_err());
    }
}
