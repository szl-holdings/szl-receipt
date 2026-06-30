# szl-receipt

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)

Shared signed-receipt library for SZL components. Provides cryptographically
signed per-inference receipts using **DSSE/ECDSA-P256-SHA256** (cosign-compatible),
with an **UNSIGNED-honest** fallback when no signing key is present.

## Install

```bash
pip install szl-receipt
```

Or from source:

```bash
pip install -e ".[dev]"
```

## Quick start

```python
from szl_receipt import Receipt, sign_receipt, verify_receipt, generate_keypair, PAYLOAD_TYPE

# 1. Build a receipt
r = Receipt(kind="inference", body={"model": "gpt-4o", "policy": "allow", "score": 0.99})
digest = r.digest()  # SHA-256 hex over canonical_json(body)

# 2a. Keyless — UNSIGNED-honest
env = sign_receipt(r, private_key_pem=None, organ="a11oy")
# env["signed"] == False, env["note"] == "UNSIGNED-honest: no cosign key present"

ok, detail = verify_receipt(env)           # -> (False, "unsigned-honest") — NEVER a fake pass

# 2b. Signed — DSSE/ECDSA-P256-SHA256
priv_pem, pub_pem = generate_keypair()
env2 = sign_receipt(r, private_key_pem=priv_pem, organ="a11oy")

ok, detail = verify_receipt(env2, public_key_pem=pub_pem)   # -> (True, "ok")
```

## Envelope schema

| Field | Type | Description |
|-------|------|-------------|
| `payloadType` | str | DSSE payload type URI |
| `payload` | str | base64(canonical_json(body)) |
| `signature` | str | base64(DER ECDSA-P256 sig), `""` when unsigned |
| `signed` | bool | `True` when real signature present |
| `organ` | str | Signing authority label |
| `keyid` | str | Optional key identifier |
| `digest` | str | SHA-256 hex of canonical_json(body) |
| `algo` | str | `"ECDSA-P256-SHA256"` or `"UNSIGNED"` |
| `note` | str | Present only when unsigned; value: `"UNSIGNED-honest: no cosign key present"` |

## cosign verification

Save the public key as `organ.pub`, then:

```bash
cosign verify-blob --key organ.pub \
    --payload <(echo -n "$payload_b64" | base64 -d) \
    --signature <(echo -n "$sig_b64" | base64 -d)
```

## Crypto doctrine

- **UNSIGNED-honest:** no key → `signed=False`, `signature=""`, and
  `verify_receipt` returns `(False, "unsigned-honest")` — NEVER a fake pass.
- **One canonical hash:** SHA-256 over `canonical_json(body)` (sorted keys,
  compact separators, UTF-8). Resolves SHA3-vs-SHA256 drift.
- **cosign-compatible:** PAE is identical to khipu-consensus — byte-for-byte
  compatible with `cosign verify-blob`.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## SPDX

SPDX-License-Identifier: Apache-2.0  
ORCID: 0009-0001-0110-4173
