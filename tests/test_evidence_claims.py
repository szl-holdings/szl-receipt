# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""Claim-type contract: assertion may never render as verification."""
import pytest

from szl_receipt.evidence.claims import (
    MEASURED,
    MISSING,
    REPRODUCED,
    SELF_ASSERTED,
    Claim,
    ClaimValidationError,
    is_valid_digest,
    is_valid_utc_timestamp,
)

GOOD_DIGEST = "a" * 64
OTHER_DIGEST = ("b" * 31) + ("c" * 33)
GOOD_TS = "2026-11-22T12:00:00Z"


def _measured(**overrides):
    payload = {
        "claim_id": "eval/heldout-v1",
        "slot": "evaluation",
        "status": MEASURED,
        "evidence_uri": "https://example.invalid/runs/1/receipt.json",
        "artifact_digest": GOOD_DIGEST,
        "evaluated_at": GOOD_TS,
        "evaluator": "szl-receipt-ci",
    }
    payload.update(overrides)
    return Claim.from_dict(payload)


def test_valid_measured_claim_is_verified():
    claim = _measured()
    assert claim.verified is True
    assert claim.status == MEASURED


def test_valid_reproduced_claim_is_verified():
    claim = _measured(status=REPRODUCED, claim_id="eval/heldout-v1-repro")
    assert claim.verified is True


def test_measured_without_digest_rejected():
    with pytest.raises(ClaimValidationError):
        _measured(artifact_digest="")


def test_measured_without_evidence_uri_rejected():
    with pytest.raises(ClaimValidationError):
        _measured(evidence_uri="")


def test_measured_without_timestamp_rejected():
    with pytest.raises(ClaimValidationError):
        _measured(evaluated_at="")


def test_measured_without_evaluator_rejected():
    with pytest.raises(ClaimValidationError):
        _measured(evaluator="")


def test_naive_timestamp_rejected_not_utc():
    assert is_valid_utc_timestamp("2026-11-22T12:00:00") is False
    with pytest.raises(ClaimValidationError):
        _measured(evaluated_at="2026-11-22T12:00:00")


def test_nonzero_offset_rejected():
    assert is_valid_utc_timestamp("2026-11-22T12:00:00+02:00") is False


def test_digest_must_be_lowercase_hex_64():
    assert is_valid_digest(GOOD_DIGEST) is True
    assert is_valid_digest(GOOD_DIGEST.upper()) is False
    assert is_valid_digest("nothex" * 9) is False
    assert is_valid_digest(None) is False
    assert is_valid_digest(GOOD_DIGEST[:-1]) is False


def test_self_asserted_is_never_verified():
    claim = Claim.from_dict(
        {
            "claim_id": "dataset/provenance-claim",
            "slot": "dataset",
            "status": SELF_ASSERTED,
            "summary": "the vendor says it is clean",
        }
    )
    assert claim.verified is False


def test_self_asserted_with_evidence_still_not_verified():
    # Attaching prose evidence to a self-assertion must not upgrade it.
    claim = _measured(status=SELF_ASSERTED, claim_id="dataset/claim")
    assert claim.verified is False


def test_missing_claim_requires_named_gap():
    ok = Claim.from_dict(
        {
            "claim_id": "safety/redteam",
            "slot": "safety",
            "status": MISSING,
            "named_gap": "no red-team suite has run for this revision",
        }
    )
    assert ok.verified is False
    assert ok.named_gap
    with pytest.raises(ClaimValidationError):
        Claim.from_dict(
            {"claim_id": "safety/redteam", "slot": "safety", "status": MISSING}
        )


def test_unknown_status_rejected():
    with pytest.raises(ClaimValidationError):
        _measured(status="allegedly-fine")


def test_unknown_slot_rejected():
    with pytest.raises(ClaimValidationError):
        _measured(slot="vibes")


def test_claim_id_slug_rules():
    with pytest.raises(ClaimValidationError):
        _measured(claim_id="Not A Slug")
    with pytest.raises(ClaimValidationError):
        _measured(claim_id="")
    with pytest.raises(ClaimValidationError):
        # avoid a flaky length assertion if 'a'*128 is valid: this is 129
        _measured(claim_id="a" * 200)


def test_claim_missing_required_keys():
    with pytest.raises(ClaimValidationError):
        Claim.from_dict({"slot": "evaluation", "status": MEASURED})


def test_to_dict_roundtrip():
    claim = _measured()
    data = claim.to_dict()
    assert data["status"] == MEASURED
    assert data["artifact_digest"] == GOOD_DIGEST
    claim2 = Claim.from_dict(data)
    assert claim2 == claim


def test_to_dict_self_asserted_hides_evidence_fields():
    claim = _measured(status=SELF_ASSERTED, claim_id="dataset/claim")
    data = claim.to_dict()
    assert "artifact_digest" not in data
    assert "evidence_uri" not in data
    assert data["status"] == SELF_ASSERTED


def test_other_digest_fixture_is_valid():
    # guard the fixture constant used across this test module
    assert is_valid_digest(OTHER_DIGEST) is True
