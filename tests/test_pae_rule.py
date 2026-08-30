# SPDX-License-Identifier: Apache-2.0
"""PAE rule proof — the B-08 migration acceptance test.

Locked rule (v11 §7.3/§7.5): the DSSE Pre-Authentication Encoding MUST
length-prefix the DECODED payload bytes — never the base64 text. A LEN field
computed over the base64 encoding is a signature-verify bypass class. The
payload_v11 §7.5 demo pins the expected preimage shape:

    PAE preimage head: b'DSSEv1 28 application/vnd.in-toto+json 1982 {"_type":"https://in'
    LEN uses decoded payload bytes: 1982 (base64 length 2644 would be a
    signature-verify bypass)

These tests prove the rule end-to-end on the pinned maintained stack:
statements constructed/validated by in-toto-attestation 0.9.3, envelopes
signed with ECDSA P-256 via cryptography 50.0.1, PAE recomputed from the
emitted envelope alone.
"""
from __future__ import annotations

import base64
import re

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from szl_receipt import (
    Receipt,
    generate_keypair,
    sign_receipt,
    verify_receipt,
)
from szl_receipt._canonical import pae
from szl_receipt._sign import PAYLOAD_TYPE
from szl_receipt.governed_action import (
    DSSE_PAYLOAD_TYPE,
    PASS,
    REQUIRED_SUBJECT_ROLES,
    emit_governed_action,
    verify_governed_action,
)

NOW = "2026-08-13T12:00:00Z"
REVISION = "1" * 40
IMAGE = "2" * 64


def _governed_inputs():
    names = {
        "github_source": "github:szl-holdings/product",
        "huggingface_repository": "hf:SZLHOLDINGS/product",
        "runtime_artifact": "oci:product",
        "deployment": "deployment:product-prod",
        "domain": "https://product.example",
        "durable_receipt": "receipt:release-42",
        "runtime_witness": "witness:provider-build-info",
    }
    algorithms = {
        "github_source": ("gitCommit", REVISION),
        "huggingface_repository": ("gitCommit", REVISION),
        "runtime_artifact": ("sha256", IMAGE),
        "deployment": ("sha256", IMAGE),
        "domain": ("sha256", "3" * 64),
        "durable_receipt": ("sha256", "4" * 64),
        "runtime_witness": ("gitCommit", REVISION),
    }
    subjects = [
        {"name": names[role], "digest": {algorithms[role][0]: algorithms[role][1]}}
        for role in REQUIRED_SUBJECT_ROLES
    ]
    evidence = {
        role: {
            "status": "VERIFIED",
            "observedAt": "2026-08-13T11:59:00Z",
            "maxAgeSeconds": 600,
            "source": f"https://evidence.example/{role}",
        }
        for role in REQUIRED_SUBJECT_ROLES
    }
    evidence["runtime_witness"].update(
        {"independent": True, "authority": "provider-runtime-witness"}
    )
    evidence["domain"]["links"] = ["deployment"]
    evidence["durable_receipt"]["links"] = [
        role for role in REQUIRED_SUBJECT_ROLES if role != "durable_receipt"
    ]
    return {
        "action": {
            "id": "release-42",
            "kind": "publish-and-promote",
            "requestedAt": "2026-08-13T11:58:00Z",
        },
        "actor": {"id": "sole-builder", "type": "human", "authenticated": True},
        "policy": {
            "id": "release-policy.v1",
            "digest": {"sha256": "5" * 64},
            "evaluated": True,
            "decision": "ALLOW",
        },
        "subjects": subjects,
        "subject_roles": names,
        "evidence": evidence,
        "obligations": [
            {
                "id": "source-runtime-identity",
                "status": "SATISFIED",
                "evidenceSubjects": [
                    "github_source",
                    "huggingface_repository",
                    "runtime_witness",
                ],
            }
        ],
        "side_effects": [
            {
                "id": "provider-deployment",
                "kind": "deployment",
                "required": True,
                "status": "COMPLETED",
                "receiptSubject": "durable_receipt",
            }
        ],
        "assessed_at": NOW,
    }


def _public_key(public_key_pem: bytes) -> ec.EllipticCurvePublicKey:
    return serialization.load_pem_public_key(public_key_pem)


def test_governed_action_pae_length_is_over_decoded_payload_bytes():
    priv_pem, pub_pem = generate_keypair()
    envelope = emit_governed_action(**_governed_inputs(), private_key_pem=priv_pem)

    decoded = base64.b64decode(envelope["payload"], validate=True)
    encoded_len = len(envelope["payload"])
    # The distinguishing witness: base64 text is strictly longer than the
    # decoded payload, so the two length fields can never coincide.
    assert len(decoded) != encoded_len

    preimage = pae(envelope["payloadType"], decoded)
    head = (
        b"DSSEv1 "
        + str(len(DSSE_PAYLOAD_TYPE.encode("utf-8"))).encode("ascii")
        + b" "
        + DSSE_PAYLOAD_TYPE.encode("utf-8")
        + b" "
        + str(len(decoded)).encode("ascii")
        + b" "
    )
    assert preimage.startswith(head)
    # Canonical JSON statement bytes follow the length prefix.
    assert preimage[len(head):] == decoded
    assert decoded.startswith(b'{"_type":"https://in-toto.io/Statement/v1"')

    # The emitted signature verifies over the decoded-bytes PAE...
    signature = base64.b64decode(envelope["signatures"][0]["sig"], validate=True)
    public_key = _public_key(pub_pem)
    public_key.verify(signature, preimage, ec.ECDSA(hashes.SHA256()))

    # ...and does NOT verify over a PAE whose LEN covers the base64 text —
    # the bypass class the locked rule excludes.
    base64_preimage = pae(
        envelope["payloadType"], envelope["payload"].encode("ascii")
    )
    with pytest.raises(InvalidSignature):
        public_key.verify(signature, base64_preimage, ec.ECDSA(hashes.SHA256()))

    # The full library-backed verification path agrees.
    result = verify_governed_action(envelope, pub_pem)
    assert result.status == PASS
    assert result.reasons == ()


def test_governed_action_pae_head_matches_locked_demo_format():
    priv_pem, _ = generate_keypair()
    envelope = emit_governed_action(**_governed_inputs(), private_key_pem=priv_pem)
    decoded = base64.b64decode(envelope["payload"], validate=True)
    preimage = pae(envelope["payloadType"], decoded)
    # v11 §7.5: b'DSSEv1 28 application/vnd.in-toto+json <len> {"_type":"https://in'
    assert re.match(
        rb'^DSSEv1 28 application/vnd\.in-toto\+json \d+ \{"_type":"https://in',
        preimage,
    ), preimage[:80]


def test_legacy_receipt_pae_length_is_over_decoded_payload_bytes():
    priv_pem, pub_pem = generate_keypair()
    receipt = Receipt(
        kind="inference", body={"model": "test-v1", "policy": "allow", "score": 0.99}
    )
    envelope = sign_receipt(receipt, private_key_pem=priv_pem, organ="a11oy")

    decoded = base64.b64decode(envelope["payload"], validate=True)
    assert len(decoded) != len(envelope["payload"])

    preimage = pae(PAYLOAD_TYPE, decoded)
    head = (
        b"DSSEv1 "
        + str(len(PAYLOAD_TYPE.encode("utf-8"))).encode("ascii")
        + b" "
        + PAYLOAD_TYPE.encode("utf-8")
        + b" "
        + str(len(decoded)).encode("ascii")
        + b" "
    )
    assert preimage.startswith(head)

    signature = base64.b64decode(envelope["signature"], validate=True)
    public_key = _public_key(pub_pem)
    public_key.verify(signature, preimage, ec.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignature):
        public_key.verify(
            signature,
            pae(PAYLOAD_TYPE, envelope["payload"].encode("ascii")),
            ec.ECDSA(hashes.SHA256()),
        )

    ok, detail = verify_receipt(envelope, public_key_pem=pub_pem)
    assert (ok, detail) == (True, "ok")
