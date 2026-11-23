//! Pre-/post-flight unmasking proxy.
//!
//! 1. Pre-flight: mask the prompt; only the masked prompt goes to the model.
//! 2. The model answers using tokens (passed in as `model_output` so the demo is offline).
//! 3. Post-flight: block if the output contains raw PII that was not in the masked prompt,
//!    flag tokens the model invented, then unmask only the PII kinds the caller's role allows.
//! Every step is appended to a hash-chained audit log; no raw PII is written to the log.

use crate::{audit, detect, names, str_field, token};
use serde_json::{json, Value};

pub fn proxy_op(i: &Value) -> Result<Value, String> {
    let key = str_field(i, "tenant_key")?;
    token::check_key(key)?;
    let fnames = names(i);
    let role = str_field(i, "role")?;
    let policy = &i["unmask_policy"];
    let allowed: Vec<String> = policy[role]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let (masked_prompt, vault, ents) = token::mask(str_field(i, "prompt")?, key, &fnames);
    let mut log = audit::Log::default();
    log.append(
        json!({"event": "preflight_mask", "role": role, "entities": ents.len(),
        "kinds": ents.iter().map(|e| e.kind.clone()).collect::<Vec<_>>()}),
    );

    let output = str_field(i, "model_output")?;
    // Raw PII in the output is a leak (the model only saw tokens) or a hallucinated identifier.
    let raw_in_output = detect::detect(output, &fnames);
    if !raw_in_output.is_empty() {
        log.append(
            json!({"event": "postflight_block", "reason": "raw PII in model output", "kinds":
            raw_in_output.iter().map(|e| e.kind.clone()).collect::<Vec<_>>()}),
        );
        return Ok(
            json!({"status": "blocked", "reason": "model output contains raw PII",
            "masked_prompt": masked_prompt, "audit_log": log.entries}),
        );
    }
    // Unmask tokens per role; tokens not in the vault were invented by the model.
    let mut text = output.to_string();
    let mut invented = Vec::new();
    let mut unmasked = 0;
    let mut kept = 0;
    let mut start = 0;
    while let Some(off) = text[start..].find("<<") {
        let s = start + off;
        let Some(len) = text[s..].find(">>") else {
            break;
        };
        let tok = text[s..s + len + 2].to_string();
        let kind = tok[2..].split('_').next().unwrap_or("").to_string();
        match vault.get(&tok) {
            Some(v) if allowed.contains(&kind) => {
                let v = v.as_str().unwrap_or("").to_string();
                text.replace_range(s..s + tok.len(), &v);
                start = s + v.len();
                unmasked += 1;
            }
            Some(_) => {
                let label = format!("[{kind} hidden]");
                text.replace_range(s..s + tok.len(), &label);
                start = s + label.len();
                kept += 1;
            }
            None => {
                invented.push(tok.clone());
                text.replace_range(s..s + tok.len(), "[unknown]");
                start = s + "[unknown]".len();
            }
        }
    }
    log.append(json!({"event": "postflight_unmask", "role": role, "unmasked": unmasked, "kept_masked": kept, "invented_tokens": invented.len()}));
    Ok(
        json!({"status": "ok", "masked_prompt": masked_prompt, "final_output": text,
        "invented_tokens": invented, "audit_log": log.entries, "head_hash": log.head()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(role: &str, out_fn: impl Fn(&str) -> String) -> Value {
        let key = "tenant-acme-key-0001";
        let prompt = "Refund jo@acme.com on card 4111 1111 1111 1111.";
        let et = token::token_for(key, "EMAIL", "jo@acme.com");
        proxy_op(&json!({"tenant_key": key, "prompt": prompt, "role": role,
            "unmask_policy": {"support": ["EMAIL"], "analyst": []},
            "model_output": out_fn(&et)}))
        .unwrap()
    }
    #[test]
    fn support_sees_email_not_card() {
        let ct = token::token_for("tenant-acme-key-0001", "CARD", "4111111111111111");
        let r = run("support", |et| format!("Email {et} about card {ct}."));
        assert_eq!(
            r["final_output"],
            "Email jo@acme.com about card [CARD hidden]."
        );
        assert!(!r["masked_prompt"].as_str().unwrap().contains("4111"));
    }
    #[test]
    fn analyst_sees_nothing() {
        let r = run("analyst", |et| format!("Contact {et}."));
        assert_eq!(r["final_output"], "Contact [EMAIL hidden].");
    }
    #[test]
    fn raw_pii_in_output_blocked() {
        let r = run("support", |_| "Send it to other@evil.com".into());
        assert_eq!(r["status"], "blocked");
    }
    #[test]
    fn invented_token_flagged() {
        let r = run("support", |_| "Also <<EMAIL_000000000000>>".into());
        assert_eq!(r["invented_tokens"].as_array().unwrap().len(), 1);
    }
}
