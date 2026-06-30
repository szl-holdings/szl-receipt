#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""
SZL — "Governed AI you can prove" — 60-second proof.

Run:  python demo_signed_receipt.py
What it shows, end-to-end, on your own hardware:
  1. An AI makes a governed decision (allow / block) with a plain reason.
  2. We mint a cryptographically SIGNED receipt of that decision (ECDSA-P256).
  3. Anyone can VERIFY the receipt — and if a single byte is tampered, it fails.
  4. With no key present, it is honestly UNSIGNED (never a fake "verified").

No competitor (NeMo, Lakera, Credo, IBM, Microsoft) ships a signed per-decision
receipt. This is the thing.
"""
from szl_receipt import Receipt, sign_receipt, verify_receipt, generate_keypair
import base64, json, copy

def line(): print("─" * 64)

print("\n  SZL — Governed AI you can prove\n")
line()

# --- 1. A governed AI decision (e.g. a11oy gating a lead outreach) -----------
decision = {
    "action": "contact_prospect",
    "subject": "lead#10023-NY",
    "model": "szl-router/llama-3.1-8b",
    "policy_pack": "tcpa-compliance.v11",
    "verdict": "block",
    "reason": "On the Do-Not-Call registry — outreach blocked (TCPA).",
    "confidence": {"level": "High", "range": [0.0, 14.9]},
    "data_basis": "public records only; no private PII",
}
print("  1) AI decision:")
print(f"       action : {decision['action']}  →  VERDICT: {decision['verdict'].upper()}")
print(f"       reason : {decision['reason']}")

# --- 2. Mint a SIGNED receipt of that decision -------------------------------
priv_pem, pub_pem = generate_keypair()          # first-boot key, on YOUR hardware
r = Receipt(kind="governance.decision", body=decision)
env = sign_receipt(r, private_key_pem=priv_pem, organ="a11oy")
print("\n  2) Signed receipt minted:")
print(f"       signed : {env['signed']}   algo: {env['algo']}")
print(f"       digest : {r.digest()[:32]}…")
print(f"       sig    : {env['signature'][:40]}…")

# --- 3. Verify it (what a regulator / customer / investor can do) ------------
ok, why = verify_receipt(env, public_key_pem=pub_pem)
print("\n  3) Independent verification:")
print(f"       verify(genuine)        → {ok}  ({why})")

tampered = copy.deepcopy(env)
body = json.loads(base64.b64decode(tampered["payload"]))
body["verdict"] = "allow"                        # attacker flips block→allow
tampered["payload"] = base64.b64encode(
    json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).decode()
ok2, why2 = verify_receipt(tampered, public_key_pem=pub_pem)
print(f"       verify(tampered)       → {ok2}  ({why2})   ← can't flip the verdict")

# --- 4. Honest when keyless --------------------------------------------------
ke = sign_receipt(r, private_key_pem=None, organ="a11oy")
ok3, why3 = verify_receipt(ke, public_key_pem=pub_pem)
print(f"       verify(no-key receipt) → {ok3}  ({why3})   ← honestly unsigned, never faked")

line()
result = "PROOF OK" if (ok and not ok2 and not ok3) else "PROOF FAILED"
print(f"  {result}: genuine verifies, tampered fails, keyless stays honest.\n")
