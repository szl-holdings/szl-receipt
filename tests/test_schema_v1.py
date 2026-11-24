"""Tests for szl_receipt.schema_v1 (canonical model receipt schema v1, rail-honesty enforced)."""

from szl_receipt.schema_v1 import (
    SchemaError, validate, validate_or_raise,
)


def _valid_receipt():
    return {
        "schema": "szl.receipt.model/v1",
        "receipt_id": "urn:szl:receipt:test-0001",
        "model_id": "SZLHOLDINGS/example-model",
        "artifacts": [
            {"path": "model.safetensors", "sha256": "a" * 64},
        ],
        "source_of_truth": {
            "github_repo": "szl-holdings/example-repo",
            "commit": "1" * 40,
        },
        "eval": [
            {
                "dataset": "SZLHOLDINGS/example-eval",
                "revision": "refs/tags/v1",
                "metric": "accuracy",
                "value": 0.9123,
                "repro_command": "python -m szl_receipt.example_eval --receipt urn:szl:receipt:test-0001",
            },
        ],
        "runtime": {
            "declared_backend": "kimi-k3.1-pro:cloud",
            "backend_true_identity": "kimi-k3.1-pro",
        },
        "provenance": {"license": "Apache-2.0"},
        "generated_at": "2026-11-23T05:10:00Z",
        "generator": "obl17 lane receipt builder v1",
    }


def test_valid_receipt_passes():
    assert validate(_valid_receipt()) == []


def test_missing_required_field_fails():
    doc = _valid_receipt()
    del doc["source_of_truth"]
    errs = validate(doc)
    assert any(e.startswith("source_of_truth") for e in errs)


def test_bad_sha256_fails():
    doc = _valid_receipt()
    doc["artifacts"][0]["sha256"] = "not-a-hash"
    errs = validate(doc)
    assert any("sha256" in e for e in errs)


def test_branch_instead_of_commit_fails():
    doc = _valid_receipt()
    doc["source_of_truth"]["commit"] = "main"
    errs = validate(doc)
    assert any("commit" in e for e in errs)


def test_aliased_rail_honest_passes():
    # honesty: claiming the astra community rail but recording its measured shared backend
    doc = _valid_receipt()
    doc["runtime"] = {
        "declared_backend": "treyleo16/gpt-6-astra",
        "backend_true_identity": "gemma4:31b",
    }
    assert validate(doc) == []


def test_aliased_rail_disguised_identity_rejected():
    # rail-aliasing: presenting the shared gemma4:31b backend as a distinct astra identity
    doc = _valid_receipt()
    doc["runtime"] = {
        "declared_backend": "treyleo16/gpt-6-astra",
        "backend_true_identity": "astra-6.2",
    }
    errs = validate(doc)
    assert any("RAIL-ALIASING" in e for e in errs)
    try:
        validate_or_raise(doc)
        raise AssertionError("expected SchemaError")
    except SchemaError:
        pass


def test_missing_backend_identity_fails():
    doc = _valid_receipt()
    del doc["runtime"]["backend_true_identity"]
    errs = validate(doc)
    assert any("backend_true_identity" in e for e in errs)


def test_explicit_default_tag_cannot_mask_shared_backend():
    for rail in (
        "treyleo16/claude-opus-5-5",
        "treyleo16/gpt-6-1-sol",
        "treyleo16/gpt-6-astra",
    ):
        doc = _valid_receipt()
        tagged = f"{rail}:latest"
        doc["runtime"] = {"declared_backend": tagged, "backend_true_identity": rail}
        assert any("RAIL-ALIASING" in error for error in validate(doc)), tagged

        doc["runtime"]["backend_true_identity"] = "gemma4:31b"
        assert validate_or_raise(doc) is True
