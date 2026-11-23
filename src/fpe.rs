//! Format-preserving encryption for digit strings.
//!
//! FF1-style balanced Feistel network, 10 rounds, radix 10, round function HMAC-SHA256 over
//! (tweak, round, length, half). Output has the same length and character set as the input,
//! so a 16-digit card number stays a 16-digit number and fits the legacy column.
//!
//! NOTE: this is a teaching implementation of the FF1 structure. It is not NIST SP 800-38G
//! validated (FF1 uses AES-CBC-MAC as PRF). Use a validated library for regulated data.

use crate::str_field;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

const ROUNDS: u8 = 10;

fn f(key: &str, tweak: &str, round: u8, n: usize, half: &str, m: usize) -> u128 {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
    mac.update(format!("{tweak}|{round}|{n}|{half}").as_bytes());
    let h = mac.finalize().into_bytes();
    let mut x = 0u128;
    for b in &h[..16] {
        x = (x << 8) | *b as u128;
    }
    x % 10u128.pow(m as u32)
}

fn pad(x: u128, m: usize) -> String {
    format!("{x:0>m$}")
}

pub fn crypt(key: &str, tweak: &str, digits: &str, encrypt: bool) -> Result<String, String> {
    let n = digits.len();
    if !(4..=36).contains(&n) || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err("input must be 4 to 36 digits".into());
    }
    if key.len() < 16 {
        return Err("key must be at least 16 bytes".into());
    }
    let u = n / 2;
    let v = n - u;
    let (mut a, mut b) = (digits[..u].to_string(), digits[u..].to_string());
    if encrypt {
        for i in 0..ROUNDS {
            let m = if i % 2 == 0 { u } else { v };
            let c =
                (a.parse::<u128>().unwrap() + f(key, tweak, i, n, &b, m)) % 10u128.pow(m as u32);
            a = std::mem::replace(&mut b, pad(c, m));
        }
    } else {
        for i in (0..ROUNDS).rev() {
            let m = if i % 2 == 0 { u } else { v };
            let modulus = 10u128.pow(m as u32);
            let c = b.parse::<u128>().unwrap();
            let prev_b = a.clone();
            let prev_a = (c + modulus - f(key, tweak, i, n, &prev_b, m)) % modulus;
            a = pad(prev_a, m);
            b = prev_b;
        }
    }
    Ok(format!("{a}{b}"))
}

/// Encrypt the digits of a formatted value, keep separators, optionally keep the last 4.
pub fn op(i: &Value, encrypt: bool) -> Result<Value, String> {
    let key = str_field(i, "key")?;
    let tweak = i["tweak"].as_str().unwrap_or("");
    let value = str_field(i, "value")?;
    let keep_last = i["keep_last"].as_u64().unwrap_or(0) as usize;
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if keep_last >= digits.len() {
        return Err("keep_last must be smaller than the digit count".into());
    }
    let (body, tail) = digits.split_at(digits.len() - keep_last);
    // The kept tail is bound into the tweak, so changing it breaks decryption.
    let out = crypt(key, &format!("{tweak}|{tail}"), body, encrypt)? + tail;
    let mut it = out.chars();
    let formatted: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                it.next().unwrap()
            } else {
                c
            }
        })
        .collect();
    Ok(json!({"result": formatted, "digits": out.len(), "kept_last": keep_last}))
}

#[cfg(test)]
mod tests {
    use super::*;
    const K: &str = "fpe-demo-key-0123456789";
    #[test]
    fn round_trip_many_lengths() {
        for n in 4..=36 {
            let d: String = (0..n)
                .map(|i| char::from(b'0' + ((i * 7 + 3) % 10) as u8))
                .collect();
            let c = crypt(K, "t", &d, true).unwrap();
            assert_eq!(c.len(), n);
            assert_ne!(c, d);
            assert_eq!(crypt(K, "t", &c, false).unwrap(), d);
        }
    }
    #[test]
    fn tweak_and_key_change_output() {
        let a = crypt(K, "t1", "4111111111111111", true).unwrap();
        assert_ne!(a, crypt(K, "t2", "4111111111111111", true).unwrap());
        assert_ne!(
            a,
            crypt("another-key-0123456", "t1", "4111111111111111", true).unwrap()
        );
    }
    #[test]
    fn formatted_with_last4() {
        let e = op(
            &json!({"key": K, "value": "4111-1111-1111-1234", "keep_last": 4}),
            true,
        )
        .unwrap();
        let s = e["result"].as_str().unwrap();
        assert!(s.ends_with("-1234") && s.len() == 19);
        let d = op(&json!({"key": K, "value": s, "keep_last": 4}), false).unwrap();
        assert_eq!(d["result"], "4111-1111-1111-1234");
    }
    #[test]
    fn rejects_bad_input() {
        assert!(crypt(K, "", "12a4", true).is_err());
        assert!(crypt(K, "", "123", true).is_err());
    }
}
