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
