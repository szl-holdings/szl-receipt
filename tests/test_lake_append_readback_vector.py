"""Negative controls for the frozen receipt -> lake v2 boundary vector."""
from __future__ import annotations

import copy
import pathlib

import pytest

from conformance import lake_append_readback as contract


VECTOR = (
    pathlib.Path(__file__).resolve().parents[1]
    / "conformance"
    / "interoperability"
    / "V06-lake-append-readback.json"
)


@pytest.fixture()
def vector():
    return contract.load_vector(VECTOR)


def test_frozen_vector_recomputes_exactly(vector):
    assert contract.verify_vector(vector) == []
    expected = vector["expected"]
    assert (
        expected["append_response"]["receipt_body_hash"]
        == expected["readback_projection"]["receipt_body_hash"]
    )
    assert (
        expected["append_response"]["chain_head"]
        == expected["readback_projection"]["chain_hash"]
    )


def test_readback_chain_head_cannot_be_relabelled(vector):
    changed = copy.deepcopy(vector)
    changed["expected"]["readback_projection"]["chain_hash"] = "0" * 64
    assert "expected does not match" in "\n".join(contract.verify_vector(changed))


def test_append_body_change_cannot_reuse_frozen_projection(vector):
    changed = copy.deepcopy(vector)
    changed["append_request"]["envelope"]["note"] = "signed"
    assert "append_request does not match" in "\n".join(
        contract.verify_vector(changed)
    )


def test_same_identity_different_body_is_a_real_negative_control(vector):
    original = vector["append_request"]
    conflict = vector["conflict_request"]
    verdict = vector["expected"]["same_identity_different_body"]
    assert original["id"] == conflict["id"] == verdict["receipt_id"]
    assert original["envelope"]["digest"] != conflict["envelope"]["digest"]
    assert verdict["expected_hash"] != verdict["received_hash"]
    assert verdict["exception"] == "ReceiptIdentityConflict"


def test_duplicate_json_members_are_refused(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON member"):
        contract.load_vector(path)


def test_contract_revision_is_not_advisory_metadata(vector):
    changed = copy.deepcopy(vector)
    changed["lake_contract"]["merge_revision"] = "0" * 40
    errors = "\n".join(contract.verify_vector(changed))
    assert "lake_contract.merge_revision must be" in errors
