# SPDX-License-Identifier: Apache-2.0
"""Keyless checks for the shared ITE-6 fail-soft validation boundary."""
import base64
import copy
import json
import sys

import pytest

from szl_receipt import _intoto
from szl_receipt.governed_action import (
    DSSE_PAYLOAD_TYPE,
    GOVERNED_ACTION_PREDICATE_TYPE,
    INCOMPLETE,
    verify_governed_action,
)


def _statement(predicate=None):
    return {
        "_type": _intoto.STATEMENT_TYPE_URI,
        "subject": [{"name": "synthetic", "digest": {"sha256": "a" * 64}}],
        "predicateType": GOVERNED_ACTION_PREDICATE_TYPE,
        "predicate": {"synthetic": True} if predicate is None else predicate,
    }


def _unsigned_envelope(statement):
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [],
    }


def _assert_structural_reason(reasons):
    structural = [reason for reason in reasons if reason.startswith("statement-ite6-invalid:")]
    assert len(structural) == 1


def test_shared_helper_normalizes_real_protobuf_integer_overflow_without_mutation():
    statement = _statement({"synthetic": 10**1000})
    before = copy.deepcopy(statement)
    _assert_structural_reason(_intoto.statement_ite6_errors(statement))
    assert statement == before


def test_shared_helper_normalizes_real_predicate_recursion_without_mutation():
    leaf = {"synthetic": True}
    predicate = leaf
    for _ in range(sys.getrecursionlimit() + 32):
        predicate = {"nested": predicate}
    statement = _statement(predicate)
    _assert_structural_reason(_intoto.statement_ite6_errors(statement))
    assert statement["predicate"] is predicate
    current = predicate
    for _ in range(sys.getrecursionlimit() + 32):
        current = current["nested"]
    assert current is leaf
    assert leaf == {"synthetic": True}


def test_unsigned_public_verifier_reports_real_protobuf_overflow_as_incomplete():
    statement = _statement({"synthetic": 10**1000})
    envelope = _unsigned_envelope(statement)
    before = copy.deepcopy(envelope)
    result = verify_governed_action(envelope)
    assert result.status == INCOMPLETE
    assert result.ok is False
    assert result.statement == statement
    assert "dsse-signature-count-not-one" in result.reasons
    _assert_structural_reason(result.reasons)
    assert envelope == before


@pytest.mark.parametrize("error_type", [OverflowError, RecursionError])
def test_public_verifier_normalizes_binding_failures_after_json_decode(monkeypatch, error_type):
    statement = _statement()
    envelope = _unsigned_envelope(statement)
    before = copy.deepcopy(envelope)

    def reject_conversion(**_kwargs):
        raise error_type("synthetic binding conversion failure")

    # Deep JSON can fail during decoding before reaching the shared helper.
    # Inject at the maintained constructor to exercise its downstream boundary.
    monkeypatch.setattr(_intoto, "Statement", reject_conversion)
    result = verify_governed_action(envelope)
    assert result.status == INCOMPLETE
    assert result.ok is False
    assert result.statement == statement
    assert "dsse-signature-count-not-one" in result.reasons
    _assert_structural_reason(result.reasons)
    assert envelope == before


def test_valid_shared_helper_preserves_original_integer_payload():
    statement = _statement({"synthetic": True, "count": 1})
    before = copy.deepcopy(statement)
    assert _intoto.statement_ite6_errors(statement) == []
    assert statement == before
    assert type(statement["predicate"]["count"]) is int


def test_structurally_valid_unsigned_public_input_remains_incomplete():
    envelope = _unsigned_envelope(_statement())
    before = copy.deepcopy(envelope)
    result = verify_governed_action(envelope)
    assert result.status == INCOMPLETE
    assert result.ok is False
    assert "dsse-signature-count-not-one" in result.reasons
    assert not any(reason.startswith("statement-ite6-invalid:") for reason in result.reasons)
    assert envelope == before
