# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
"""
Tests for the PCGI one-call unifier: emit_receipt / verify_receipt.

These exercise the doctrine-critical properties of the spine:
  * determinism — identical inputs -> byte-identical canonical body/digest/payload,
  * honest UNAVAILABLE energy (and rejection of fabricated joules),
  * a signed receipt verifies end-to-end (envelope signature + in-toto binding),
  * tamper (payload, body, statement subject) is rejected,
  * keyless emission stays UNSIGNED-honest (never a fake pass),
  * output reuses the EXISTING shapes (envelope verifiable by the core verifier).
"""
import base64
import copy
import hashlib

import pytest

from szl_receipt import (
    emit_receipt,
    generate_keypair,
    verify_emitted_receipt,
    verify_receipt as verify_envelope,
)
from szl_receipt._canonical import canonical_json
from szl_receipt.attest import UNAVAILABLE, IN_TOTO_STATEMENT_TYPE
from szl_receipt.sdk import PCGI_PREDICATE_TYPE, PCGI_SCHEMA


def _emit(priv=None, **overrides):
    kwargs = dict(
        model_id="szl-router/llama-3.1-8b",
        input_digest="a" * 64,
        output_digest="b" * 64,
        policy_id="tcpa-compliance.v11",
        organ="a11oy",
        private_key_pem=priv,
    )
    kwargs.update(overrides)
    return emit_receipt(**kwargs)


# --- determinism -----------------------------------------------------------
def test_deterministic_canonical_body_and_digest():
    r1 = _emit(energy_joules=None)
    r2 = _emit(energy_joules=None)
    # Byte-identical canonical body -> identical digest and identical payload.
    assert canonical_json(r1["body"]) == canonical_json(r2["body"])
    assert r1["digest"] == r2["digest"]
    assert r1["envelope"]["payload"] == r2["envelope"]["payload"]
    # Digest is exactly sha256(canonical_json(body)).
    assert r1["digest"] == hashlib.sha256(canonical_json(r1["body"])).hexdigest()


def test_signature_nonce_differs_but_binding_is_stable():
    priv, _ = generate_keypair()
    r1 = _emit(priv=priv)
    r2 = _emit(priv=priv)
    # Same bound content...
    assert r1["digest"] == r2["digest"]
    # ...but ECDSA carries a random nonce, so signatures differ.
    assert r1["envelope"]["signature"] != r2["envelope"]["signature"]


# --- honest energy ---------------------------------------------------------
def test_energy_unavailable_when_unmeasured():
    r = _emit(energy_joules=None)
    assert r["body"]["energy"] == UNAVAILABLE
    comp = {c["id"]: c for c in r["compliance"]["controls"]}
    assert comp["NIST-AI-RMF-MEASURE-2.x"]["status"] == UNAVAILABLE
    assert r["compliance"]["measured_energy"] is False


def test_energy_measured_stored_verbatim():
    r = _emit(energy_joules=42.5)
    assert r["body"]["energy"] == {"joules": 42.5, "unit": "J"}
    comp = {c["id"]: c for c in r["compliance"]["controls"]}
    assert comp["NIST-AI-RMF-MEASURE-2.x"]["status"] == "supports"
    assert r["compliance"]["measured_energy"] is True


def test_fabricated_energy_is_rejected():
    # A bool is not a real measurement — never coerce True -> 1 joule.
    with pytest.raises(ValueError):
        _emit(energy_joules=True)
    with pytest.raises(ValueError):
        _emit(energy_joules="lots")


# --- binding + signature verify -------------------------------------------
def test_binds_all_pcgi_fields():
    r = _emit(energy_joules=7, witnesses=[{"node": "n1", "sig": "s1"}])
    b = r["body"]
    assert b["schema"] == PCGI_SCHEMA
    assert b["model_id"] == "szl-router/llama-3.1-8b"
    assert b["input_digest"] == "a" * 64
    assert b["output_digest"] == "b" * 64
    assert b["policy_id"] == "tcpa-compliance.v11"
    assert b["witnesses"] == [{"node": "n1", "sig": "s1"}]
    # Statement is a real in-toto v1 bound to the body digest.
    assert r["statement"]["_type"] == IN_TOTO_STATEMENT_TYPE
    assert r["statement"]["subject"][0]["digest"]["sha256"] == r["digest"]


def test_signed_receipt_verifies_end_to_end():
    priv, pub = generate_keypair()
    r = _emit(priv=priv, energy_joules=12.0)
    ok, why = verify_emitted_receipt(r, public_key_pem=pub)
    assert ok is True, why
    assert why == "ok"
    # predicate_type gate also passes when correct.
    ok2, _ = verify_emitted_receipt(
        r, public_key_pem=pub, predicate_type=PCGI_PREDICATE_TYPE
    )
    assert ok2 is True


def test_envelope_is_drop_in_for_core_verifier():
    # The emitted envelope reuses the EXISTING shape: the core verify_receipt
    # (envelope-level) verifies it with no changes.
    priv, pub = generate_keypair()
    r = _emit(priv=priv)
    ok, why = verify_envelope(r["envelope"], public_key_pem=pub)
    assert ok is True, why


# --- tamper rejection ------------------------------------------------------
def test_tamper_payload_is_rejected():
    priv, pub = generate_keypair()
    r = _emit(priv=priv)
    tampered = copy.deepcopy(r)
    payload_bytes = base64.b64decode(tampered["envelope"]["payload"])
    flipped = bytes([payload_bytes[0] ^ 0x01]) + payload_bytes[1:]
    tampered["envelope"]["payload"] = base64.b64encode(flipped).decode("ascii")
    ok, why = verify_emitted_receipt(tampered, public_key_pem=pub)
    assert ok is False
    assert why != "ok"


def test_tamper_body_field_is_rejected():
    priv, pub = generate_keypair()
    r = _emit(priv=priv)
    tampered = copy.deepcopy(r)
    # Attacker flips the governing policy in the plaintext body only.
    tampered["body"]["policy_id"] = "no-such-policy"
    ok, why = verify_emitted_receipt(tampered, public_key_pem=pub)
    assert ok is False
    assert why == "body-payload-mismatch"


def test_tamper_statement_subject_is_rejected():
    priv, pub = generate_keypair()
    r = _emit(priv=priv)
    tampered = copy.deepcopy(r)
    tampered["statement"]["subject"][0]["digest"]["sha256"] = "deadbeef"
    ok, why = verify_emitted_receipt(tampered, public_key_pem=pub)
    assert ok is False
    assert why == "statement-subject-digest-not-bound"


# --- keyless honesty -------------------------------------------------------
def test_keyless_is_unsigned_honest():
    r = _emit(priv=None)
    assert r["envelope"]["signed"] is False
    assert r["envelope"]["signature"] == ""
    assert r["compliance"]["signed"] is False
    ok, why = verify_emitted_receipt(r)  # no key at all
    assert ok is False
    assert why == "unsigned-honest"
    priv2, pub2 = generate_keypair()
    ok2, why2 = verify_emitted_receipt(r, public_key_pem=pub2)  # wrong/unrelated key
    assert ok2 is False
    assert why2 == "unsigned-honest"


# --- graceful on malformed input ------------------------------------------
def test_verify_is_graceful_on_garbage():
    assert verify_emitted_receipt(None) == (False, "not-a-receipt")
    assert verify_emitted_receipt({}) == (False, "no-envelope")


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-q"]))
