# SPDX-License-Identifier: Apache-2.0
"""Offline positioned-profile contract; only disposable in-memory sample keys."""

import base64
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from szl_receipt import Receipt, generate_keypair, sign_receipt, verify_receipt
from szl_receipt.positioned import (
    KeyWindow,
    sign_positioned_receipt,
    verify_positioned_receipt,
)

TYPE = "application/vnd.szl.receipt.positioned.v1.audit+json"


@pytest.fixture(scope="module")
def keys():
    return generate_keypair()


@pytest.fixture
def window(keys):
    return KeyWindow(keys[1], "ledger-A", "audit", 5, 10)


def emit(keys, position=7, body=None, kind="audit"):
    return sign_positioned_receipt(
        Receipt(kind, body if body is not None else {"event": "ok"}),
        keys[0],
        log_id="ledger-A",
        position=position,
    )


def framing(kind, raw):
    # Independent DSSE wire framing; deliberately not the production helper.
    media = kind.encode("ascii")
    return b"DSSEv1 %d %s %d %s" % (len(media), media, len(raw), raw)


def sign_raw(envelope, private_pem, raw):
    private = serialization.load_pem_private_key(private_pem, None)
    der = private.sign(framing(TYPE, raw), ec.ECDSA(hashes.SHA256()))
    return {
        **envelope,
        "payload": base64.b64encode(raw).decode(),
        "signatures": [
            {**envelope["signatures"][0], "sig": base64.b64encode(der).decode()}
        ],
    }


def test_jcs_and_domain_are_the_exact_signed_bytes(keys, window):
    body = {"\ue000": 1e20, "\U00010000": [-0.0, 1e-7, 4.5]}
    raw = '{"body":{"𐀀":[0,1e-7,4.5],"":100000000000000000000},"log_id":"ledger-A","position":7}'.encode()
    envelope = emit(keys, body=body)
    assert envelope["payloadType"] == TYPE
    assert base64.b64decode(envelope["payload"]) == raw
    public = serialization.load_pem_public_key(keys[1])
    public.verify(
        base64.b64decode(envelope["signatures"][0]["sig"]),
        framing(TYPE, raw),
        ec.ECDSA(hashes.SHA256()),
    )
    assert verify_positioned_receipt(envelope, window=window, expected_position=7) == (
        True,
        "ok",
    )


def test_independent_openssl_verifies_new_profile_coverage(keys):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("OpenSSL not installed")
    envelope = emit(keys)
    raw = base64.b64decode(envelope["payload"])
    # Only the public key and public signature enter this temporary directory.
    with TemporaryDirectory() as tmp:
        pub, sig = Path(tmp) / "public.pem", Path(tmp) / "signature.der"
        pub.write_bytes(keys[1])
        sig.write_bytes(base64.b64decode(envelope["signatures"][0]["sig"]))
        args = [openssl, "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig)]
        for kind, expected_ok in [
            (TYPE, True),
            (TYPE.replace("audit", "release"), False),
        ]:
            run = subprocess.run(
                args, input=framing(kind, raw), capture_output=True, check=False
            )
            assert (run.returncode == 0) is expected_ok


@pytest.mark.parametrize("position", [5, 7, 10])
def test_window_includes_both_boundaries(position, keys, window):
    assert verify_positioned_receipt(
        emit(keys, position), window=window, expected_position=position
    ) == (True, "ok")


@pytest.mark.parametrize("position", [4, 11, True, 7.0, "7", -1, 2**53])
def test_trusted_position_outside_window_or_wrong_type(position, keys, window):
    assert verify_positioned_receipt(
        emit(keys), window=window, expected_position=position
    ) == (False, "position-outside-key-window")


def test_window_must_match_signed_log_position_kind_and_key(keys, window):
    envelope = emit(keys)
    for policy, pos, reason in [
        (window, 8, "position-or-log-mismatch"),
        (replace(window, log_id="ledger-B"), 7, "position-or-log-mismatch"),
        (replace(window, kind="release"), 7, "payload-type-mismatch"),
        (replace(window, public_key_pem=generate_keypair()[1]), 7, "key-id-mismatch"),
    ]:
        assert verify_positioned_receipt(
            envelope, window=policy, expected_position=pos
        ) == (False, reason)
    release = emit(keys, kind="release")
    assert release["payload"] == envelope["payload"]
    assert verify_positioned_receipt(
        {**release, "payloadType": TYPE}, window=window, expected_position=7
    ) == (False, "signature-mismatch")


@pytest.mark.parametrize(("first", "last"), [(9, 8), (-1, 7), (True, 1), (0, 2**53)])
def test_invalid_trusted_configuration_is_not_a_policy(first, last, keys):
    with pytest.raises(ValueError):
        KeyWindow(keys[1], "ledger-A", "audit", first, last)


def test_retirement_uses_verifier_position_not_signer_claim(keys, window):
    successor_keys = generate_keypair()
    successor = KeyWindow(successor_keys[1], window.log_id, window.kind, 11, 20)
    # The predecessor can still produce a valid signature over position 10.
    # It cannot re-use that signed position at the independently observed slot 11.
    before = emit(keys, 10)
    assert verify_positioned_receipt(before, window=window, expected_position=10) == (
        True,
        "ok",
    )
    assert not verify_positioned_receipt(before, window=window, expected_position=11)[0]
    assert not verify_positioned_receipt(
        emit(keys, 11), window=successor, expected_position=11
    )[0]
    assert verify_positioned_receipt(
        emit(successor_keys, 11), window=successor, expected_position=11
    ) == (True, "ok")


@pytest.mark.parametrize(
    "body",
    [
        {1: "not a string key"},
        {"n": float("nan")},
        {"n": float("inf")},
        {"n": 2**53 + 1},
        {"s": "\ud800"},
    ],
)
def test_signer_refuses_non_jcs_input(body, keys):
    with pytest.raises(ValueError):
        emit(keys, body=body)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"body": {"x":0},"log_id":"ledger-A","position":7}',  # whitespace
        b'{"body":{"x":1,"x":1},"log_id":"ledger-A","position":7}',
        b'{"body":{"x":9007199254740993},"log_id":"ledger-A","position":7}',
        b'{"body":{"x":-0.0},"log_id":"ledger-A","position":7}',
        b'{"body":{"x":NaN},"log_id":"ledger-A","position":7}',
        b'{"body":{},"log_id":"ledger-A","position":true}',
        b'{"body":[],"log_id":"ledger-A","position":7}',
        b'{"body":{},"log_id":"ledger-A","position":7,"trust":true}',
    ],
)
def test_genuine_signature_alone_does_not_admit_invalid_records(raw, keys, window):
    envelope = sign_raw(emit(keys), keys[0], raw)
    assert not verify_positioned_receipt(envelope, window=window, expected_position=7)[
        0
    ]


def test_reject_envelope_supplied_policy_unknown_fields_and_missing_evidence(
    keys, window
):
    envelope = emit(keys)
    sig = envelope["signatures"][0]
    for patch in [
        {"window": {"first": 0, "last": 100}},
        {"signed": True},
        {"signatures": None},
        {"payload": "%%%"},
        {"signatures": [sig, sig]},
        {"signatures": [{"sig": sig["sig"]}]},
        {"signatures": [{**sig, "keyid": "unknown"}]},
        {"signatures": [{**sig, "sig": ""}]},
    ]:
        assert not verify_positioned_receipt(
            {**envelope, **patch}, window=window, expected_position=7
        )[0]


def test_keyless_and_legacy_profiles_do_not_cross_verify(keys, window):
    receipt = Receipt("audit", {"n": -0.0})
    unsigned = sign_positioned_receipt(receipt, None, log_id="ledger-A", position=7)
    assert unsigned["signatures"] == []
    assert verify_positioned_receipt(unsigned, window=window, expected_position=7) == (
        False,
        "unsigned-honest",
    )
    legacy = sign_receipt(receipt, keys[0])
    assert base64.b64decode(legacy["payload"]) == b'{"n":-0.0}'
    assert verify_receipt(legacy, keys[1]) == (True, "ok")
    assert not verify_positioned_receipt(legacy, window=window, expected_position=7)[0]
    assert not verify_receipt(emit(keys), keys[1])[0]
