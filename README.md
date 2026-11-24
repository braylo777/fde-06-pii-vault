# fde-06-pii-vault

**Forward Deployed Engineering — Stage 6 of 12: PII Cryptography & Guardrails**

Find personal data, swap it for deterministic tokens before the model sees it, unmask only what a role may see, and keep a tamper-evident log of every step.

**Also built as Project 6 of 12, "Deterministic PII Unmasking Proxy",** from the companion [12 FDE projects post](https://x.com/suraj_sharma14/status/2125197762752806998).

**Live demo:** https://fde-06-pii-vault.braylo777.workers.dev — the Rust core runs in your browser as WebAssembly. No server, no tracking.

## Why this matters

Legal will not sign off on an LLM project until they know where customer PII goes. The answer that works: the model never sees raw PII. Values are swapped for keyed tokens on the way in, the output is checked on the way out, and only the roles that need a value get it back. Card numbers that must stay in legacy systems are encrypted without changing their format, and the audit log can prove nobody edited it.

## What it does

- Detectors with validation: email, phone, SSN rules, cards (Luhn), IBAN (mod-97), IPv4, rule-based person names (titles + first-name list)
- Deterministic tokens: HMAC-SHA256 per tenant key, value normalization, so the same customer gets the same token across documents
- Proxy: pre-flight mask, post-flight block on raw PII, detection of tokens the model invented, unmask per role
- Format-preserving encryption for digit strings (FF1-style Feistel), keep-last-4, separators kept
- Hash-chained audit log with tamper, delete, reorder and truncation (anchored head) detection

## What it does not do (yet)

- Person-name NER is rule-based, not a trained model: plug in spaCy / Presidio for production recall
- The FPE is FF1-shaped but uses HMAC, not AES; it is not NIST SP 800-38G validated
- No key management: keys are inputs here; use a KMS / HSM and rotate per tenant
- No real LLM call: model_output is given, so the demo runs offline

## Operations

Every operation takes JSON in and gives JSON out. The CLI, the tests and the demo page all use the same entry point.

| Operation | What it does |
|---|---|
| `detect` | Validated detectors: the second card number fails Luhn and the order number is ignored, so neither is flagged. |
| `tokenize` | Each value becomes a keyed token. Change the tenant_key and every token changes; run it twice and they stay the same. |
| `proxy` | The model saw only tokens. A support agent gets the name, email and phone back, but the card stays hidden, and the model's invented token becomes [unknown]. Switch role to fraud_analyst or bi_dashboard. |
| `fpe_encrypt` | The card stays 16 digits with dashes and keeps its last 4, so it still fits the legacy column and the receipt UI. |
| `fpe_decrypt` | Same key and tweak reverse it. A different tweak gives a different, wrong result. |
| `audit_verify` | This is the proxy's audit log with one field edited after the fact. Verification names the entry. Undo the edit (entities back to 4) to see valid: true. |

## Run it

You need Rust (stable). No Node, no npm.

```bash
git clone https://github.com/braylo777/fde-06-pii-vault
cd fde-06-pii-vault
cargo test
cargo run -- ops
```

Try the first demo example from the command line:

```bash
python3 -c 'import json;print(json.dumps(json.load(open("web/examples.json"))["ops"][0]["input"]))' | cargo run -q -- detect
```

## Build and deploy the demo

```bash
./build.sh    # tests, then compiles the core to web/app.wasm
./deploy.sh   # serves web/ as a Cloudflare Workers static-assets site (needs a Cloudflare login)
```

`web/` is a plain static site (`index.html`, `app.js`, `app.wasm`). It has no build step, so any static host works.

## Layout

```
src/lib.rs        operation list and router
src/api.rs        JSON entry point + the 3 WASM exports (alloc, dealloc, run)
src/main.rs       CLI
src/*.rs          one module per capability, each with unit tests
tests/            integration tests (every demo example must pass)
web/              demo page; examples.json drives both the page and this README
```

## Design choices

- **Rust, few dependencies.** Only `serde`, `serde_json`, `sha2` and `hmac`, pinned to exact versions with a committed `Cargo.lock`.
- **Deterministic.** Time, randomness and keys are inputs, so every result can be replayed in a test or an audit.
- **Fail closed.** Unknown input, missing fields or an unmatched policy gives an error or a denial, never a silent pass.

## Part of a series

This is one of 12 repos that work through a public Forward Deployed Engineering roadmap ([12 stages](https://x.com/suraj_sharma14/status/2124827808535048566), [12 projects](https://x.com/suraj_sharma14/status/2125197762752806998)). All 12: [github.com/braylo777?q=fde-](https://github.com/braylo777?tab=repositories&q=fde-).

## License

MIT — see [LICENSE](LICENSE). Built by [Braylo SI](https://braylo.si).
