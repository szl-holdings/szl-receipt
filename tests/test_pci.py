# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
"""Tests for the Proof-Carrying Inference (PCI) profile and the Λ kernel."""
from __future__ import annotations

import copy
import math

import pytest

from szl_receipt import generate_keypair
from szl_receipt import lambda_gate as lg
from szl_receipt.pci import (
    FORBIDDEN_CLAIMS,
    PCI_PROFILE,
    SpecRef,
    emit_pci_receipt,
    verify_pci_receipt,
)
from szl_receipt.sdk import emit_receipt

# --------------------------------------------------------------------------- #
# Λ kernel (lambda_gate)                                                       #
# --------------------------------------------------------------------------- #

def test_lambda_weighted_geometric_mean():
    # 0.5**0.5 * 0.5**0.5 == 0.5
    lam = lg.lambda_score({"a": 0.5, "b": 0.5}, {"a": 0.5, "b": 0.5})
    assert math.isclose(lam, 0.5, abs_tol=1e-12)
    # Π equal scores == that score
    lam2 = lg.lambda_score({"a": 0.8, "b": 0.8}, {"a": 0.25, "b": 0.75})
    assert math.isclose(lam2, 0.8, abs_tol=1e-12)


def test_lambda_is_non_compensatory():
    # One zeroed axis collapses the whole aggregate — cannot be bought back.
    lam = lg.lambda_score({"a": 0.0, "b": 1.0}, {"a": 0.01, "b": 0.99})
    assert lam == 0.0


def test_lambda_rejects_bad_weights_and_scores():
    with pytest.raises(lg.LambdaGateError):
        lg.lambda_score({"a": 0.5, "b": 0.5}, {"a": 0.4, "b": 0.4})  # sum != 1
    with pytest.raises(lg.LambdaGateError):
        lg.lambda_score({"a": 1.5}, {"a": 1.0})  # score > 1
    with pytest.raises(lg.LambdaGateError):
        lg.lambda_score({"a": True}, {"a": 1.0})  # bool is not a real score
    with pytest.raises(lg.LambdaGateError):
        lg.lambda_score({"a": 0.5}, {"b": 1.0})  # axis mismatch


def test_evaluate_pass_and_fail():
    v = lg.evaluate({"a": 0.9, "b": 0.9}, {"a": 0.5, "b": 0.5}, theta=0.8)
    assert v.verdict == "advisory-pass" and v.lam >= 0.8
    v2 = lg.evaluate({"a": 0.9, "b": 0.1}, {"a": 0.5, "b": 0.5}, theta=0.8)
    assert v2.verdict == "advisory-fail" and v2.lam < 0.8


# --------------------------------------------------------------------------- #
# PCI emit / verify                                                           #
# --------------------------------------------------------------------------- #

def _good_verdict():
    return lg.evaluate({"safety": 0.95, "provenance": 0.9}, {"safety": 0.5, "provenance": 0.5}, theta=0.8)


def test_signed_roundtrip_advisory_pass():
    priv, pub = generate_keypair()
    r = emit_pci_receipt(
        model_id="gpt-4o", input_digest="in", output_digest="out",
        policy_id="pol-1", lambda_verdict=_good_verdict(),
        energy_joules=12.5, organ="a11oy", private_key_pem=priv,
    )
    assert r["body"]["extra"]["pci_profile"] == PCI_PROFILE
    res = verify_pci_receipt(r, public_key_pem=pub, require_measured_energy=True)
    assert res.ok is True
    assert res.advisory == "advisory-pass"
    assert res.energy == "MEASURED"
    assert res.signed is True


def test_advisory_fail_is_still_a_valid_receipt():
    priv, pub = generate_keypair()
    weak = lg.evaluate({"safety": 0.2, "provenance": 0.9}, {"safety": 0.5, "provenance": 0.5}, theta=0.8)
    r = emit_pci_receipt(
        model_id="m", input_digest="i", output_digest="o", policy_id="p",
        lambda_verdict=weak, organ="a11oy", private_key_pem=priv,
    )
    res = verify_pci_receipt(r, public_key_pem=pub)
    assert res.ok is True                      # integrity/honesty hold
    assert res.advisory == "advisory-fail"     # but the advisory verdict is negative
    assert res.reason == "ok:advisory-fail"


def test_keyless_is_unsigned_honest():
    r = emit_pci_receipt(
        model_id="m", input_digest="i", output_digest="o", policy_id="p",
        lambda_verdict=_good_verdict(), organ="a11oy", private_key_pem=None,
    )
    res = verify_pci_receipt(r)
    assert res.ok is False and res.reason == "unsigned-honest"


def test_require_measured_energy_rejects_unavailable():
    priv, pub = generate_keypair()
    r = emit_pci_receipt(
        model_id="m", input_digest="i", output_digest="o", policy_id="p",
        lambda_verdict=_good_verdict(), energy_joules=None,
        organ="a11oy", private_key_pem=priv,
    )
    res = verify_pci_receipt(r, public_key_pem=pub, require_measured_energy=True)
    assert res.ok is False and res.reason == "energy-unavailable"
    # ...but without the flag it verifies, honestly labelled UNAVAILABLE.
    res2 = verify_pci_receipt(r, public_key_pem=pub)
    assert res2.ok is True and res2.energy == "UNAVAILABLE"


def test_tamper_body_is_rejected_by_the_spine():
    priv, pub = generate_keypair()
    r = emit_pci_receipt(
        model_id="m", input_digest="i", output_digest="o", policy_id="p",
        lambda_verdict=_good_verdict(), organ="a11oy", private_key_pem=priv,
    )
    tampered = copy.deepcopy(r)
    tampered["body"]["policy_id"] = "no-such-policy"
    res = verify_pci_receipt(tampered, public_key_pem=pub)
    assert res.ok is False and res.reason == "body-payload-mismatch"


def test_wrong_lambda_is_caught_by_recompute():
    # A self-signed receipt whose recorded Λ was computed wrong: the signature
    # is valid over the (wrong) body, but offline recomputation catches it.
    priv, pub = generate_keypair()
    bad_extra = {
        "pci_profile": PCI_PROFILE,
        "lambda_verdict": {
            "kernel": "szl-lambda-gate", "form": "weighted-geometric-mean",
            "scores": {"a": 0.5, "b": 0.5}, "weights": {"a": 0.5, "b": 0.5},
            "theta": 0.1, "lambda": 0.99, "verdict": "advisory-pass", "note": "x",
        },
        "spec": SpecRef().to_dict(),
        "attestation": {"status": "UNAVAILABLE"},
    }
    r = emit_receipt(
        model_id="m", input_digest="i", output_digest="o", policy_id="p",
        organ="a11oy", private_key_pem=priv, extra=bad_extra,
    )
    res = verify_pci_receipt(r, public_key_pem=pub)
    assert res.ok is False and res.reason == "lambda-recompute-mismatch"


def test_tier_guard_refuses_overclaims():
    priv, pub = generate_keypair()
    for claim, expected in FORBIDDEN_CLAIMS.items():
        r = emit_pci_receipt(
            model_id="m", input_digest="i", output_digest="o", policy_id="p",
            lambda_verdict=_good_verdict(), spec=SpecRef(claims=[claim]),
            organ="a11oy", private_key_pem=priv,
        )
        res = verify_pci_receipt(r, public_key_pem=pub)
        assert res.ok is False and res.reason == expected


def test_verify_is_graceful_on_garbage():
    assert verify_pci_receipt(None).ok is False
    assert verify_pci_receipt({}).ok is False


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-q"]))
