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

## Proof-Carrying Inference (PCI)

PCI is a receipt **profile** layered on the PCGI spine. Where PCGI binds
`model + input + output + policy + energy` (+ BFT witnesses), PCI adds the two
bindings that make a governed decision **offline-verifiable** as a governance
warrant — a receipt `R = ⟨π, τ, ε, (Λ ≥ θ, σ)⟩`:

| Field | Binding | Backing kernel |
|-------|---------|----------------|
| `π` | provenance / DSSE envelope + in-toto statement | `szl-receipt` (this repo) |
| `τ` | confidential-execution attestation *(○ specified; roadmap)* | — |
| `ε` | measured energy, joules **verbatim or `UNAVAILABLE`** | `szl-energy-attest` |
| `Λ ≥ θ` | non-compensatory roll-up `Λ = Π xᵢ^wᵢ`, **re-computed on verify** | `szl-lambda-gate` |
| `σ` | machine-checked spec reference + **tier guard** | `lutar-lean` (locked tier) |

Both PCI bindings ride inside the sanctioned PCGI `extra` extension point, so
they are part of the signed body digest — tamper-evident — **without forking the
spine**. `verify_pci_receipt` first runs the existing spine verifier, then
**recomputes Λ** from the bound scores (a wrong Λ is caught offline, not merely
asserted) and enforces the **tier guard**.

```python
from szl_receipt import generate_keypair, lambda_gate as lg
from szl_receipt.pci import SpecRef, emit_pci_receipt, verify_pci_receipt

verdict = lg.evaluate(
    scores={"safety": 0.96, "provenance": 0.90},
    weights={"safety": 0.5, "provenance": 0.5},
    theta=0.80,
)                                              # Λ = weighted geometric mean

priv, pub = generate_keypair()
r = emit_pci_receipt(
    model_id="szl-router/llama-3.1-8b",
    input_digest="sha256:in…", output_digest="sha256:out…",
    policy_id="tcpa-compliance.v11",
    lambda_verdict=verdict, spec=SpecRef(), energy_joules=12.5,
    organ="a11oy", private_key_pem=priv,
)

res = verify_pci_receipt(r, public_key_pem=pub, require_measured_energy=True)
# res.ok is True, res.advisory == "advisory-pass", res.energy == "MEASURED"
```

Runnable end-to-end demo: [`examples/proof_carrying_inference.py`](examples/proof_carrying_inference.py).

### PCI honesty doctrine (never weakened)

- **Λ is advisory.** A pass clears a non-compensatory threshold — it is **not** a
  proof of correctness, safety, or conformity.
- **Λ recomputed, not trusted.** The verifier recomputes `Λ = Π xᵢ^wᵢ` from the
  bound scores; a producer's wrong Λ fails offline (`lambda-recompute-mismatch`).
- **Tier guard refuses overclaims — by allowlist, not denylist.** Spec `claims`
  are validated against a fixed allowlist of honest tokens, so no overclaim
  survives *however it is reworded*. The specific machine-checked non-theorems —
  unconditional Λ-uniqueness (**Conjecture 1, false as stated** →
  `overclaim-conjecture1`) and unconditional Khipu BFT safety (**Conjecture 2,
  open** → `overclaim-conjecture2`) — are refused with their exact reason code,
  scanned across `claims` **and** `invariants`. Λ-uniqueness is **conditional**
  (Theorem U). `locked_count` is derived from the invariant list so it cannot
  drift.
- **Energy is measured-or-`UNAVAILABLE`.** `require_measured_energy=True` refuses
  a receipt lacking a real joule reading, and a non-finite `joules` value is
  refused as `energy-malformed` — a joule is never fabricated.
- **Attestation (τ) is honest-only.** Confidential-execution verification is not
  yet implemented, so only the `UNAVAILABLE` placeholder passes; a receipt
  asserting a "verified" enclave we cannot check is refused
  (`attestation-unverifiable`).
- **Keyless stays UNSIGNED-honest** — `verify_pci_receipt` returns
  `unsigned-honest`, never a fake pass.

### Prior art (cited, not claimed as ours)

- G. Necula, *Proof-Carrying Code*, POPL 1997, [doi:10.1145/263699.263712](https://doi.org/10.1145/263699.263712).
- Kol, Ben-Shahar, Sulimany, Englund, *A machine-verified proof of a
  quantum-optimization conjecture*, [arXiv:2606.29687](https://arxiv.org/abs/2606.29687) (2026) —
  LLM proposes / Lean 4 certifies, the loop SZL points at governance rather than
  pure mathematics.
- SZL corpus concept DOI: [10.5281/zenodo.19944926](https://doi.org/10.5281/zenodo.19944926).

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## SPDX

SPDX-License-Identifier: Apache-2.0  
ORCID: 0009-0001-0110-4173
