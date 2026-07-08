# SPDX-License-Identifier: Apache-2.0
"""
Tests 1-3: sign->verify roundtrip, tamper detection, keyless honesty.
"""
import base64

import pytest

from szl_receipt import Receipt, generate_keypair, sign_receipt, verify_receipt


@pytest.fixture()
def keypair():
    return generate_keypair()


@pytest.fixture()
def receipt():
    return Receipt(kind="inference", body={"model": "test-v1", "policy": "allow", "score": 0.99})


# Test 1 — sign -> verify roundtrip
def test_sign_verify_roundtrip(keypair, receipt):
    priv_pem, pub_pem = keypair
    env = sign_receipt(receipt, private_key_pem=priv_pem, organ="a11oy")

    assert env["signed"] is True
    assert env["signature"] != ""
    assert env["algo"] == "ECDSA-P256-SHA256"

    ok, detail = verify_receipt(env, public_key_pem=pub_pem)
    assert ok is True, f"verify failed: {detail}"
    assert detail == "ok"


# Test 2 — tamper detection: flip one character in the payload b64
def test_tamper_detection(keypair, receipt):
    priv_pem, pub_pem = keypair
    env = sign_receipt(receipt, private_key_pem=priv_pem, organ="a11oy")

    # Decode -> flip a byte -> re-encode
    payload_bytes = base64.b64decode(env["payload"])
    tampered_bytes = bytes([payload_bytes[0] ^ 0x01]) + payload_bytes[1:]
    tampered_env = dict(env)
    tampered_env["payload"] = base64.b64encode(tampered_bytes).decode("ascii")

    ok, detail = verify_receipt(tampered_env, public_key_pem=pub_pem)
    assert ok is False
    assert detail == "signature mismatch"


# Test 3 — keyless honesty
def test_keyless_honesty(keypair, receipt):
    _, pub_pem = keypair

    # Unsigned envelope
    env = sign_receipt(receipt, private_key_pem=None, organ="a11oy")
    assert env["signed"] is False
    assert env["signature"] == ""
    assert env["note"] == "UNSIGNED-honest: no cosign key present"

    # verify must NEVER return True for an unsigned envelope
    ok, detail = verify_receipt(env, public_key_pem=pub_pem)
    assert ok is False
    assert detail == "unsigned-honest"

    # Also without supplying a pub key
    ok2, detail2 = verify_receipt(env)
    assert ok2 is False
    assert detail2 == "unsigned-honest"


# Test 6 — the signed envelope's advisory digest equals the body digest
def test_signed_envelope_digest_matches_body(keypair, receipt):
    priv_pem, _ = keypair
    env = sign_receipt(receipt, private_key_pem=priv_pem, organ="a11oy")
    assert env["digest"] == receipt.digest()


# Test 7 — digest binding: a valid signature + intact payload but a forged
# ``digest`` field (which rides OUTSIDE the signed PAE bytes) is refused, so a
# consumer that references a receipt by envelope["digest"] cannot be misdirected.
def test_forged_digest_field_is_rejected(keypair, receipt):
    priv_pem, pub_pem = keypair
    env = sign_receipt(receipt, private_key_pem=priv_pem, organ="a11oy")

    # Sanity: untouched envelope verifies.
    ok, detail = verify_receipt(env, public_key_pem=pub_pem)
    assert ok is True and detail == "ok"

    # Flip the advisory digest to another well-formed but wrong sha256 hex.
    forged_env = dict(env)
    forged_env["digest"] = "0" * 64
    assert forged_env["digest"] != env["digest"]

    ok2, detail2 = verify_receipt(forged_env, public_key_pem=pub_pem)
    assert ok2 is False
    assert detail2 == "digest-mismatch"


# Test 8 — backward compatibility: an envelope with no digest field still
# verifies purely on its signature (the digest binding is additive, not required).
def test_absent_digest_still_verifies(keypair, receipt):
    priv_pem, pub_pem = keypair
    env = sign_receipt(receipt, private_key_pem=priv_pem, organ="a11oy")
    no_digest_env = dict(env)
    no_digest_env.pop("digest", None)

    ok, detail = verify_receipt(no_digest_env, public_key_pem=pub_pem)
    assert ok is True
    assert detail == "ok"
