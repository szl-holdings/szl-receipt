# SPDX-License-Identifier: Apache-2.0
"""
Tests 4-5: deterministic canonical_json/pae vectors; stable digest.
"""
import hashlib
import struct

from szl_receipt import Receipt, PAYLOAD_TYPE
from szl_receipt._canonical import canonical_json, pae


# Test 4a — canonical_json sorts keys and uses compact separators
def test_canonical_json_sorted_keys():
    result = canonical_json({"b": 1, "a": 2})
    assert result == b'{"a":2,"b":1}', f"Got: {result!r}"


def test_canonical_json_nested():
    result = canonical_json({"z": {"y": 1, "x": 0}, "a": [3, 2, 1]})
    assert result == b'{"a":[3,2,1],"z":{"x":0,"y":1}}'


def test_canonical_json_unicode():
    result = canonical_json({"msg": "héllo"})
    assert result == '{"msg":"héllo"}'.encode("utf-8")


# Test 4b — pae matches khipu's byte format exactly
def test_pae_format():
    pt = PAYLOAD_TYPE.encode("utf-8")
    body = b'{"a":1}'

    result = pae(PAYLOAD_TYPE, body)

    # DSSEv1 SP <8-byte-LE len(pt)> <pt> SP <8-byte-LE len(body)> <body>
    expected = (
        b"DSSEv1 "
        + struct.pack("<Q", len(pt))
        + pt
        + b" "
        + struct.pack("<Q", len(body))
        + body
    )
    assert result == expected, f"\nGot:      {result!r}\nExpected: {expected!r}"


def test_pae_empty_body():
    result = pae("application/x-test", b"")
    pt = b"application/x-test"
    expected = b"DSSEv1 " + struct.pack("<Q", len(pt)) + pt + b" " + struct.pack("<Q", 0)
    assert result == expected


# Test 5 — digest() is stable (same body -> same hash across calls)
def test_digest_stable():
    body = {"model": "gpt-4o", "score": 0.95, "policies": ["p1", "p2"]}
    r1 = Receipt(kind="inference", body=body)
    r2 = Receipt(kind="inference", body=body)
    assert r1.digest() == r2.digest()


def test_digest_matches_sha256_of_canonical_json():
    body = {"model": "test", "result": "pass"}
    r = Receipt(kind="test", body=body)
    expected = hashlib.sha256(canonical_json(body)).hexdigest()
    assert r.digest() == expected


def test_digest_differs_for_different_bodies():
    r1 = Receipt(kind="inference", body={"a": 1})
    r2 = Receipt(kind="inference", body={"a": 2})
    assert r1.digest() != r2.digest()
