# SPDX-License-Identifier: Apache-2.0
"""Synthetic signature-success only: no private keys or network required."""
from unittest.mock import patch

import pytest

from szl_receipt.receipt import Receipt, sign_receipt, verify_receipt

def _envelope():
    env = sign_receipt(Receipt("audit", {"decision": "deny"}), None)
    env.update({"signed": True, "signature": "fixture-signature", "algo": "ECDSA-P256-SHA256"})
    return env

def _verify(env):
    # Isolates the envelope's claim-validation boundary, not crypto validation.
    with patch("szl_receipt.receipt.verify_dsse", return_value=(True, "ok")):
        return verify_receipt(env, b"fixture-public-key")

@pytest.mark.parametrize("bad_flag", ["true", 1, None, "yes", [True], {"v": 1}])
def test_non_boolean_signed_claim_cannot_pass(bad_flag):
    env = _envelope()
    env["signed"] = bad_flag
    assert _verify(env) == (False, "unsigned-honest")

def test_missing_signed_claim_cannot_pass():
    env = _envelope()
    del env["signed"]
    assert _verify(env) == (False, "unsigned-honest")

@pytest.mark.parametrize("wrong_algo", ["UNSIGNED", "ED25519", "", None, 42])
def test_mislabeled_algorithm_cannot_pass(wrong_algo):
    env = _envelope()
    env["algo"] = wrong_algo
    assert _verify(env) == (False, "algorithm-mismatch")

def test_real_signed_metadata_unchanged():
    assert _verify(_envelope()) == (True, "ok")

def test_old_envelope_without_advisory_algo_remains_verifiable():
    env = _envelope()
    del env["algo"]
    assert _verify(env) == (True, "ok")

def test_genuinely_unsigned_never_admitted():
    env = _envelope()
    env["signed"] = False
    assert _verify(env) == (False, "unsigned-honest")
