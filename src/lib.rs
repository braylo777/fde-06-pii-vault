//! Stage 6 — PII Cryptography & Guardrails.
//!
//! * `detect` — PII detectors with validation, not just patterns: email, phone, US SSN
//!   (area/group/serial rules), payment cards (Luhn), IBAN (mod-97), IPv4, and rule-based
//!   person-name NER (titles + a first-name gazetteer).
//! * `token`  — deterministic tokens: HMAC-SHA256(key, type|value) → `<<EMAIL_1a2b3c4d5e6f>>`.
//!   The same value always maps to the same token under one key, so joins and analytics still
//!   work on masked data, but tokens cannot be reversed without the vault.
//! * `proxy`  — pre-flight masking of the prompt, post-flight checks on the model output
//!   (raw PII leak, invented tokens) and role-gated unmasking.
//! * `fpe`    — format-preserving encryption for digit strings (FF1-style Feistel with an
//!   HMAC round function); a 16-digit card stays 16 digits.
//! * `audit`  — append-only, hash-chained audit log; any edit or deletion breaks the chain.

mod api;
pub mod audit;
pub mod detect;
pub mod fpe;
pub mod proxy;
pub mod token;

pub use api::dispatch;
use serde_json::{json, Value};

pub const OPS: &[&str] = &["detect", "tokenize", "proxy", "fpe_encrypt", "fpe_decrypt", "audit_verify"];

pub(crate) fn str_field<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k).and_then(Value::as_str).ok_or_else(|| format!("missing string field `{k}`"))
}
pub(crate) fn names(i: &Value) -> Vec<String> {
    i["known_first_names"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

pub fn handle(op: &str, i: &Value) -> Result<Value, String> {
    match op {
        "detect" => Ok(json!({"entities": detect::detect(str_field(i, "text")?, &names(i))})),
        "tokenize" => token::tokenize_op(i),
        "proxy" => proxy::proxy_op(i),
        "fpe_encrypt" => fpe::op(i, true),
        "fpe_decrypt" => fpe::op(i, false),
        "audit_verify" => audit::verify_op(i),
        _ => Err(format!("unknown op `{op}`; known: {}", OPS.join(", "))),
    }
}
