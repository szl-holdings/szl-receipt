# SPDX-License-Identifier: Apache-2.0
"""Admission and adversarial contracts for GovernedAction v1."""
from __future__ import annotations

import base64
import copy
import json

from szl_receipt import generate_keypair
from szl_receipt.governed_action import (
    INCOMPLETE,
    PASS,
    REQUIRED_SUBJECT_ROLES,
    dsse_pae,
    emit_governed_action,
    verify_governed_action,
)

NOW = "2026-08-13T12:00:00Z"
REVISION = "1" * 40
IMAGE = "2" * 64


def _inputs():
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


def _signed(inputs=None):
    private_key, public_key = generate_keypair()
    envelope = emit_governed_action(
        **(inputs or _inputs()), private_key_pem=private_key
    )
    return envelope, public_key


def test_dsse_pae_uses_standard_decimal_lengths():
    assert dsse_pae("text/plain", b"abc") == b"DSSEv1 10 text/plain 3 abc"


def test_complete_signed_multi_subject_action_passes():
    envelope, public_key = _signed()
    result = verify_governed_action(envelope, public_key)
    assert result.status == PASS
    assert result.ok is True
    assert result.reasons == ()
    assert result.statement is not None
    assert len(result.statement["subject"]) == len(REQUIRED_SUBJECT_ROLES)
    assert result.statement["predicate"]["assessment"] == {
        "status": PASS,
        "reasons": [],
    }


def test_missing_subject_is_incomplete_not_pass():
    inputs = _inputs()
    inputs["subjects"] = [
        subject
        for subject in inputs["subjects"]
        if subject["name"] != inputs["subject_roles"]["domain"]
    ]
    envelope, public_key = _signed(inputs)
    result = verify_governed_action(envelope, public_key)
    assert result.status == INCOMPLETE
    assert "missing-subject:domain" in result.reasons


def test_contradictory_source_revisions_are_incomplete():
    inputs = _inputs()
    hf_name = inputs["subject_roles"]["huggingface_repository"]
    next(subject for subject in inputs["subjects"] if subject["name"] == hf_name)[
        "digest"
    ]["gitCommit"] = "6" * 40
    envelope, public_key = _signed(inputs)
    result = verify_governed_action(envelope, public_key)
    assert "contradictory-source-revisions" in result.reasons
    assert result.ok is False


def test_stale_evidence_is_incomplete():
    inputs = _inputs()
    inputs["evidence"]["github_source"]["observedAt"] = "2026-08-13T10:00:00Z"
    inputs["evidence"]["github_source"]["maxAgeSeconds"] = 60
    envelope, public_key = _signed(inputs)
    result = verify_governed_action(envelope, public_key)
    assert "evidence-stale:github_source" in result.reasons


def test_unsigned_envelope_is_incomplete_even_with_a_public_key():
    _, public_key = generate_keypair()
    envelope = emit_governed_action(**_inputs(), private_key_pem=None)
    result = verify_governed_action(envelope, public_key)
    assert result.status == INCOMPLETE
    assert "dsse-signature-count-not-one" in result.reasons
    assert "signature-not-present" in result.reasons


def test_payload_tamper_breaks_signature():
    envelope, public_key = _signed()
    tampered = copy.deepcopy(envelope)
    statement = json.loads(base64.b64decode(tampered["payload"]))
    statement["predicate"]["action"]["id"] = "release-43"
    tampered["payload"] = base64.b64encode(
        json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    result = verify_governed_action(tampered, public_key)
    assert result.status == INCOMPLETE
    assert "signature-mismatch" in result.reasons


def test_unsatisfied_obligation_is_incomplete():
    inputs = _inputs()
    inputs["obligations"][0]["status"] = "UNKNOWN"
    envelope, public_key = _signed(inputs)
    result = verify_governed_action(envelope, public_key)
    assert "obligation-unsatisfied:source-runtime-identity" in result.reasons


def test_required_side_effect_without_receipt_is_incomplete():
    inputs = _inputs()
    inputs["side_effects"][0]["status"] = "NOT_PERFORMED"
    inputs["side_effects"][0].pop("receiptSubject")
    envelope, public_key = _signed(inputs)
    result = verify_governed_action(envelope, public_key)
    assert "side-effect-required-incomplete:provider-deployment" in result.reasons


def test_runtime_witness_must_be_independent_of_actor():
    inputs = _inputs()
    inputs["evidence"]["runtime_witness"]["authority"] = "sole-builder"
    envelope, public_key = _signed(inputs)
    result = verify_governed_action(envelope, public_key)
    assert "runtime-witness-authority-not-independent" in result.reasons


def test_malformed_links_fail_closed_without_raising():
    inputs = _inputs()
    inputs["evidence"]["durable_receipt"]["links"] = [{"role": "deployment"}]
    envelope, public_key = _signed(inputs)
    result = verify_governed_action(envelope, public_key)
    assert result.status == INCOMPLETE
    assert "durable-receipt-links-incomplete" in result.reasons
