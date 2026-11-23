//! Append-only, hash-chained audit log.
//! hash_n = SHA-256(hash_{n-1} || canonical JSON of entry_n), hash_0 seed = 64 zeros.
//! Editing, reordering or deleting any entry changes every later hash.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Default)]
pub struct Log {
    pub entries: Vec<Value>,
}

pub fn link(prev: &str, seq: u64, event: &Value) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(json!({"seq": seq, "event": event}).to_string().as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

impl Log {
    pub fn head(&self) -> String {
        self.entries
            .last()
            .and_then(|e| e["hash"].as_str())
            .unwrap_or(GENESIS)
            .to_string()
    }
    pub fn append(&mut self, event: Value) {
        let seq = self.entries.len() as u64;
        let prev = self.head();
        let hash = link(&prev, seq, &event);
        self.entries
            .push(json!({"seq": seq, "event": event, "prev": prev, "hash": hash}));
    }
}

pub fn verify(entries: &[Value]) -> Result<String, String> {
    let mut prev = GENESIS.to_string();
    for (i, e) in entries.iter().enumerate() {
        if e["seq"].as_u64() != Some(i as u64) {
            return Err(format!("entry {i}: sequence gap or reorder"));
        }
        if e["prev"].as_str() != Some(prev.as_str()) {
            return Err(format!(
                "entry {i}: prev hash does not match entry {}",
                i as i64 - 1
            ));
        }
        let want = link(&prev, i as u64, &e["event"]);
        if e["hash"].as_str() != Some(want.as_str()) {
            return Err(format!("entry {i}: content was modified"));
        }
        prev = want;
    }
    Ok(prev)
}

pub fn verify_op(i: &Value) -> Result<Value, String> {
    let entries = i["entries"].as_array().ok_or("`entries` must be a list")?;
    let expected_head = i["expected_head"].as_str();
    Ok(match verify(entries) {
        Ok(head) if expected_head.map(|h| h != head).unwrap_or(false) => {
            json!({"valid": false, "error": "chain is internally consistent but its head does not match the anchored head (entries truncated?)"})
        }
        Ok(head) => json!({"valid": true, "entries": entries.len(), "head": head}),
        Err(e) => json!({"valid": false, "error": e}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Log {
        let mut l = Log::default();
        for n in 0..4 {
            l.append(json!({"event": "x", "n": n}));
        }
        l
    }
    #[test]
    fn valid_chain() {
        assert!(verify(&sample().entries).is_ok());
    }
    #[test]
    fn edit_detected() {
        let mut e = sample().entries;
        e[1]["event"]["n"] = json!(99);
        assert!(verify(&e).unwrap_err().contains("entry 1"));
    }
    #[test]
    fn delete_detected() {
        let mut e = sample().entries;
        e.remove(2);
        assert!(verify(&e).is_err());
    }
    #[test]
    fn truncation_needs_anchor() {
        let l = sample();
        let head = l.head();
        let short = &l.entries[..3];
        assert!(verify(short).is_ok());
        let r = verify_op(&json!({"entries": short, "expected_head": head})).unwrap();
        assert_eq!(r["valid"], false);
    }
}
