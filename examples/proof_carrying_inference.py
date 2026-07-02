#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors · ORCID 0009-0001-0110-4173
"""
SZL — Proof-Carrying Inference (PCI) — 60-second offline proof.

Run:  python examples/proof_carrying_inference.py

PCI extends the PCGI spine (model+input+output+policy+energy) with the two
bindings that make a governed decision an OFFLINE-VERIFIABLE governance warrant:

  * a Λ-verdict — the non-compensatory weighted-geometric-mean roll-up
    Λ = Π xᵢ**wᵢ, RE-COMPUTED by the verifier (not merely asserted);
  * a machine-checked spec reference (σ) with a TIER GUARD that refuses
    overclaims (unconditional Λ-uniqueness = Conjecture 1, machine-checked false
    as stated).

Prior art it stands on (cited, not claimed): Necula, Proof-Carrying Code
(POPL 1997); Kol/Ben-Shahar/Sulimany/Englund, arXiv:2606.29687 (2026).
"""
import copy

from szl_receipt import generate_keypair
from szl_receipt import lambda_gate as lg
from szl_receipt.pci import SpecRef, emit_pci_receipt, verify_pci_receipt


def line() -> None:
    print("─" * 66)


print("\n  SZL — Proof-Carrying Inference: a receipt you can re-check offline\n")
line()

# --- 1. A governed AI decision + its Λ governance roll-up --------------------
verdict = lg.evaluate(
    scores={"safety": 0.96, "provenance": 0.90, "energy_budget": 0.88},
    weights={"safety": 0.5, "provenance": 0.3, "energy_budget": 0.2},
    theta=0.80,
)
print("  1) Λ governance roll-up (non-compensatory weighted geometric mean):")
print(f"       Λ = {verdict.lam:.4f}   θ = {verdict.theta}   → {verdict.verdict}")

# --- 2. Mint ONE signed PCI receipt binding decision + Λ + σ (spec) ----------
priv_pem, pub_pem = generate_keypair()  # first-boot key, on YOUR hardware
r = emit_pci_receipt(
    model_id="szl-router/llama-3.1-8b",
    input_digest="sha256:in…",
    output_digest="sha256:out…",
    policy_id="tcpa-compliance.v11",
    lambda_verdict=verdict,
    spec=SpecRef(),               # lutar-lean locked tier, no overclaims
    energy_joules=12.5,           # measured; None would be honest UNAVAILABLE
    organ="a11oy",
    private_key_pem=priv_pem,
)
print("\n  2) Signed PCI receipt minted:")
print(f"       signed  : {r['envelope']['signed']}   digest: {r['digest'][:24]}…")
print(f"       profile : {r['body']['extra']['pci_profile']}")

# --- 3. Independent OFFLINE verification (Λ is re-computed, not trusted) ------
res = verify_pci_receipt(r, public_key_pem=pub_pem, require_measured_energy=True)
print("\n  3) Offline verification:")
print(f"       verify(genuine)     → ok={res.ok}  advisory={res.advisory}  "
      f"energy={res.energy}  Λ={res.lambda_value:.4f}")

# tamper: attacker inflates the recorded Λ in the plaintext body
tampered = copy.deepcopy(r)
tampered["body"]["extra"]["lambda_verdict"]["lambda"] = 0.999
t = verify_pci_receipt(tampered, public_key_pem=pub_pem)
print(f"       verify(tampered Λ)  → ok={t.ok}  ({t.reason})   ← signature binds it")

# --- 4. Tier guard: the verifier REFUSES a machine-checked non-theorem -------
over = emit_pci_receipt(
    model_id="m", input_digest="i", output_digest="o", policy_id="p",
    lambda_verdict=verdict,
    spec=SpecRef(claims=["lambda-uniqueness-unconditional"]),  # Conjecture 1
    organ="a11oy", private_key_pem=priv_pem,
)
o = verify_pci_receipt(over, public_key_pem=pub_pem)
print("\n  4) Honesty tier guard:")
print(f"       verify(overclaim)   → ok={o.ok}  ({o.reason})   ← won't certify a non-theorem")

# --- 5. Keyless stays UNSIGNED-honest — never a fake pass --------------------
keyless = emit_pci_receipt(
    model_id="m", input_digest="i", output_digest="o", policy_id="p",
    lambda_verdict=verdict, organ="a11oy", private_key_pem=None,
)
k = verify_pci_receipt(keyless)
print(f"\n  5) Keyless emission     → ok={k.ok}  ({k.reason})   ← honest, not faked\n")
line()
print("  A PCI receipt is EVIDENCE, re-checkable by anyone, offline. It is not a")
print("  claim of correctness — Λ is advisory and overclaims are refused.\n")
