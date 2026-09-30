"""Adversarial structural checks use only unsigned synthetic statements."""
import copy

import pytest

from szl_receipt import Receipt, attest, sign_receipt, verify_receipt
from szl_receipt._intoto import statement_from_parts


DIGEST = "a" * 64


def _statement():
    return attest.build_statement(
        subject_name="synthetic-receipt", subject_digest=DIGEST,
        predicate={"synthetic": True}, predicate_type="https://example.test/predicate/v1",
    )


@pytest.mark.parametrize("field", ["subject", "predicateType", "predicate"])
def test_matching_digest_cannot_replace_required_structure(field):
    statement = _statement()
    del statement[field]
    assert attest.verify_statement(statement, expected_digest=DIGEST) == (
        False, "invalid-statement-structure",
    )


@pytest.mark.parametrize("value", [None, [], {}, "", False, 1])
@pytest.mark.parametrize("field", ["subject", "predicateType", "predicate"])
def test_malformed_required_structure_is_rejected(field, value):
    statement = _statement()
    statement[field] = value
    assert attest.verify_statement(statement, expected_digest=DIGEST) == (
        False, "invalid-statement-structure",
    )


@pytest.mark.parametrize("subject", [
    None, [], "subject", 1, {}, {"digest": {"sha256": DIGEST}},
    {"name": "", "digest": {"sha256": DIGEST}},
    {"name": 1, "digest": {"sha256": DIGEST}},
    *[{"name": "bad", "digest": value} for value in
      (None, [], "digest", 1, {}, {"sha256": None}, {"sha256": 1},
       {"sha256": True}, {"sha256": ""}, {"": DIGEST}, {1: DIGEST},
       {"sha256": DIGEST, "other": []})],
])
@pytest.mark.parametrize("position", ["only", "before-valid", "after-valid"])
def test_every_subject_is_validated_even_when_another_digest_matches(subject, position):
    statement = _statement()
    valid = statement["subject"][0]
    statement["subject"] = {
        "only": [subject], "before-valid": [subject, valid], "after-valid": [valid, subject],
    }[position]
    assert attest.verify_statement(statement, expected_digest=DIGEST) == (
        False, "invalid-statement-structure",
    )


@pytest.mark.parametrize("argument", [None, "", False, 1, [], {}])
def test_invalid_binding_arguments_never_match_or_raise(argument):
    statement = _statement()
    assert attest.verify_statement(statement, expected_digest=argument) == (
        False, "invalid-expected-digest",
    )
    assert attest.verify_statement(statement, expected_digest=DIGEST, digest_alg=argument) == (
        False, "invalid-digest-algorithm",
    )


def test_null_expected_digest_cannot_match_absent_algorithm():
    statement = _statement()
    statement["subject"][0]["digest"] = {"other": "synthetic"}
    assert attest.verify_statement(statement, expected_digest=None)[0] is False


def test_valid_multiple_subjects_and_other_algorithms_keep_exact_binding():
    statement = _statement()
    statement["subject"].insert(0, {"name": "another", "digest": {"sha256": "b" * 64}})
    statement["subject"][1]["digest"]["sha512"] = "c" * 128
    before = copy.deepcopy(statement)
    assert attest.verify_statement(statement, expected_digest=DIGEST) == (True, "ok")
    assert attest.verify_statement(
        statement, expected_digest="c" * 128, digest_alg="sha512",
    ) == (True, "ok")
    assert attest.verify_statement(statement, expected_digest="d" * 64) == (
        False, "subject-digest-not-bound",
    )
    assert statement == before


@pytest.mark.parametrize("digest", [{"sha256": None}, {"sha256": 1},
                                     {"sha256": False}, {1: DIGEST}, {"": DIGEST}])
def test_builder_does_not_coerce_digest_parts(digest):
    with pytest.raises(ValueError):
        statement_from_parts(subjects=[{"name": "synthetic", "digest": digest}],
                             predicate_type="https://example.test/v1", predicate={"ok": True})


def test_unrepresentable_predicate_fails_without_echo_or_exception():
    statement = _statement()
    statement["predicate"] = {"synthetic": 10**1000}
    assert attest.verify_statement(statement, expected_digest=DIGEST) == (
        False, "invalid-statement-structure",
    )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"),
                                   {"nested": [float("nan")]}, {"nested": float("inf")}])
def test_nonfinite_predicate_is_rejected_by_builder_and_verifier(value):
    statement = _statement()
    statement["predicate"] = {"synthetic": value}
    assert attest.verify_statement(statement, expected_digest=DIGEST) == (
        False, "invalid-statement-structure",
    )
    with pytest.raises(ValueError):
        attest.build_statement(subject_name="synthetic", subject_digest=DIGEST,
                               predicate=statement["predicate"])


def test_cyclic_predicate_is_a_fixed_structural_failure():
    statement = _statement()
    statement["predicate"]["cycle"] = statement["predicate"]
    assert attest.verify_statement(statement, expected_digest=DIGEST) == (
        False, "invalid-statement-structure",
    )


@pytest.mark.parametrize("field,value", [
    ("uri", 1), ("uri", None), ("content", {"not": "base64"}), ("content", "@@@"),
    ("content", None), ("downloadLocation", []), ("mediaType", False),
    ("annotations", []), ("annotations", None), ("annotations", {"bad": float("nan")}),
])
def test_malformed_optional_subject_fields_cannot_hide_behind_matching_digest(field, value):
    statement = _statement()
    statement["subject"][0][field] = value
    assert attest.verify_statement(statement, expected_digest=DIGEST) == (
        False, "invalid-statement-structure",
    )


def test_valid_optional_subject_fields_and_extensions_preserve_original_values():
    statement = _statement()
    statement["subject"][0].update({
        "uri": "https://example.test/receipt", "mediaType": "application/json",
        "downloadLocation": "https://example.test/download", "content": "e30=",
        "annotations": {"synthetic": True, "count": 1}, "extension": {"version": 1},
    })
    statement["predicate"]["count"] = 1
    before = copy.deepcopy(statement)
    assert attest.verify_statement(statement, expected_digest=DIGEST) == (True, "ok")
    assert statement == before
    assert type(statement["predicate"]["count"]) is int


@pytest.mark.parametrize("value", [float("nan"), object(), {"nested": float("inf")}])
def test_non_json_top_level_extensions_fail_closed(value):
    statement = _statement()
    statement["extension"] = value
    assert attest.verify_statement(statement, expected_digest=DIGEST) == (
        False, "invalid-statement-structure",
    )


def test_structural_success_does_not_authenticate_an_unsigned_receipt():
    receipt = Receipt(kind="synthetic", body={"synthetic": True})
    envelope = sign_receipt(receipt, private_key_pem=None)
    statement = attest.build_statement(subject_name="synthetic", subject_digest=receipt.digest(),
                                       predicate={"synthetic": True})
    assert attest.verify_statement(statement, expected_digest=receipt.digest()) == (True, "ok")
    assert envelope["signed"] is False
    assert verify_receipt(envelope) == (False, "unsigned-honest")
