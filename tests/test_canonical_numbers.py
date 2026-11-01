# SPDX-License-Identifier: Apache-2.0
"""Finite JSON numbers at the shared hashing and signing boundary."""
import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from szl_receipt import Receipt, generate_keypair, sign_receipt, verify_receipt
from szl_receipt._canonical import canonical_json, pae
from szl_receipt._sign import PAYLOAD_TYPE, sign_dsse, verify_dsse
from szl_receipt.pci import verify_pci_receipt
from szl_receipt.sdk import emit_receipt
from szl_receipt.sdk import verify_receipt as verify_composite


@pytest.fixture(params=[float("nan"), float("inf"), float("-inf")],
                ids=["nan", "positive-infinity", "negative-infinity"])
def nonfinite(request):
    return request.param


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair()


def legacy_signed_envelope(body, keypair):
    """Sign pre-fix bytes without using the serializer under test."""
    payload = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=True,
    ).encode("utf-8")
    private_pem, public_pem = keypair
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    signing_bytes = pae(PAYLOAD_TYPE, payload)
    signature = private_key.sign(signing_bytes, ec.ECDSA(hashes.SHA256()))
    # This really is a valid signature over these exact bytes. A rejection by
    # a receipt verifier must come from its JSON profile, not a broken fixture.
    public_key = serialization.load_pem_public_key(public_pem)
    public_key.verify(signature, signing_bytes, ec.ECDSA(hashes.SHA256()))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
        "signed": True,
        "digest": hashlib.sha256(payload).hexdigest(),
    }


@pytest.mark.parametrize("shape", ["scalar", "list", "nested", "key"])
def test_canonical_json_rejects_nonfinite_at_any_depth(nonfinite, shape):
    values = {
        "scalar": nonfinite,
        "list": [0, nonfinite],
        "nested": {"evidence": [{"measurement": nonfinite}]},
        "key": {nonfinite: "measurement"},
    }
    with pytest.raises(ValueError):
        canonical_json(values[shape])


def test_digest_and_signing_reject_nonfinite_before_emission(nonfinite, keypair):
    private_pem, _ = keypair
    body = {"evidence": [{"measurement": nonfinite}]}
    receipt = Receipt(kind="audit", body=body)

    with pytest.raises(ValueError):
        receipt.digest()
    with pytest.raises(ValueError):
        sign_dsse(body, private_pem)
    for key in (None, private_pem):
        with pytest.raises(ValueError):
            sign_receipt(receipt, private_key_pem=key)


@pytest.mark.parametrize("field", ["energy_joules", "extra", "witnesses"])
def test_sdk_rejects_nonfinite_measurements_and_extensions(nonfinite, field):
    fields = {
        "energy_joules": nonfinite,
        "extra": {"observations": [{"value": nonfinite}]},
        "witnesses": [{"weight": nonfinite}],
    }
    with pytest.raises(ValueError):
        emit_receipt(
            model_id="sample", input_digest="a" * 64,
            output_digest="b" * 64, policy_id="sample-policy",
            **{field: fields[field]},
        )


def test_valid_signature_over_nonfinite_legacy_payload_fails_closed(nonfinite, keypair):
    _, public_pem = keypair
    body = {"evidence": [{"measurement": nonfinite}]}
    envelope = legacy_signed_envelope(body, keypair)

    assert verify_receipt(envelope, public_pem) == (False, "signature mismatch")
    ok, detail = verify_dsse(body, envelope["signature"], public_pem)
    assert ok is False
    assert detail.startswith("invalid key or encoding:")
    assert verify_composite({"body": body, "envelope": envelope}, public_pem) == (
        False, "body-canonicalization-error"
    )
    pci = verify_pci_receipt({"body": body, "envelope": envelope}, public_pem)
    assert pci.ok is False
    assert pci.reason == "body-canonicalization-error"
    # Omitting the advisory body must not bypass validation of the payload.
    assert verify_composite({"envelope": envelope}, public_pem) == (
        False, "signature mismatch"
    )


def test_finite_bytes_digests_and_existing_signatures_stay_compatible(keypair):
    private_pem, public_pem = keypair
    body = {
        "unicode": "caf\u00e9", "strings": ["NaN", "Infinity", "-Infinity"],
        "numbers": [0, -0.0, 1.5, 1e-20, 1e20, 9007199254740993],
        "nested": {"present": True, "absent": None},
    }
    expected = (
        '{"nested":{"absent":null,"present":true},'
        '"numbers":[0,-0.0,1.5,1e-20,1e+20,9007199254740993],'
        '"strings":["NaN","Infinity","-Infinity"],"unicode":"caf\u00e9"}'
    ).encode("utf-8")
    legacy_envelope = legacy_signed_envelope(body, keypair)
    receipt = Receipt(kind="audit", body=body)

    assert canonical_json(body) == expected
    assert receipt.digest() == hashlib.sha256(expected).hexdigest()
    assert verify_receipt(legacy_envelope, public_pem) == (True, "ok")
    for key in (None, private_pem):
        envelope = sign_receipt(receipt, private_key_pem=key)
        assert base64.b64decode(envelope["payload"]) == expected
        assert envelope["digest"] == legacy_envelope["digest"]
        expected_verdict = (False, "unsigned-honest") if key is None else (True, "ok")
        assert verify_receipt(envelope, public_pem) == expected_verdict
