# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 SZL Contributors
"""Actual adapter controls, frozen policy mutations and strict-unavailable CLI."""
from __future__ import annotations

import base64
import copy
import dataclasses
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("szl_fixture_verifier_benchmark", ROOT / "conformance/benchmark_verifiers.py")
benchmark = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = benchmark
spec.loader.exec_module(benchmark)


@pytest.fixture(scope="module")
def bundle():
    return benchmark.build_fixture_bundle()


@pytest.fixture(scope="module")
def openssl():
    return benchmark.OpenSSLVerifier()


@pytest.fixture
def fixture_directory():
    # Use our own ephemeral directory: an existing shared pytest-of-user tree
    # may have unrelated ACLs and must not be modified to run this benchmark.
    with tempfile.TemporaryDirectory(prefix="szl-benchmark-test-") as directory:
        yield Path(directory)


def _case(bundle, name):
    return next(case for case in bundle.cases if case.name == name)


@pytest.mark.parametrize("name", [
    "valid", "payload_tamper", "payload_type_tamper", "signature_tamper",
    "wrong_verification_key", "pretty_json_unchanged_signature", "pretty_json_resigned",
    "advisory_digest_tamper", "unsigned", "signed_wrong_artifact",
    "valid_signer_not_admitted", "signed_wrong_source_revision",
])
def test_actual_cryptography_profile_and_policy_matrix(bundle, name):
    case = _case(bundle, name)
    checks = {"cryptography": benchmark.verify_raw_signature(case.envelope, case.verification_key_pem),
              "receipt_profile": benchmark.verify_profile(case.envelope, case.verification_key_pem),
              **benchmark.verify_fixture_policy(case.envelope, case.verification_key_pem, bundle.artifact, bundle.policy)}
    for field, result in checks.items():
        assert result["evidence_class"] == "MEASURED"
        assert result["accepted"] is case.expected[field]


@pytest.mark.parametrize("name", ["valid", "payload_tamper", "payload_type_tamper", "signature_tamper",
                                 "wrong_verification_key", "pretty_json_unchanged_signature", "pretty_json_resigned",
                                 "advisory_digest_tamper", "unsigned", "signed_wrong_artifact",
                                 "valid_signer_not_admitted", "signed_wrong_source_revision"])
def test_actual_external_adapter_matrix(bundle, openssl, name):
    if not openssl.available:
        pytest.skip("OpenSSL unavailable; strict-unavailable control remains mandatory")
    case = _case(bundle, name)
    result = openssl.verify(case.envelope, case.verification_key_pem)
    assert result["evidence_class"] == "MEASURED", result
    assert result["accepted"] is case.expected["cryptography"], result
    payload, signature, signing = benchmark._decode(case.envelope)
    assert result["command"]["stdin_sha256"] == benchmark.sha256(signing)
    assert result["command"]["signature_der_sha256"] == benchmark.sha256(signature)
    assert "private" not in " ".join(result["command"]["argv"])


def test_semantic_negatives_have_valid_signatures(bundle):
    for name in ("signed_wrong_artifact", "valid_signer_not_admitted", "signed_wrong_source_revision"):
        case = _case(bundle, name)
        assert benchmark.verify_raw_signature(case.envelope, case.verification_key_pem)["accepted"] is True
        assert benchmark.verify_profile(case.envelope, case.verification_key_pem)["accepted"] is True
        checks = benchmark.verify_fixture_policy(case.envelope, case.verification_key_pem, bundle.artifact, bundle.policy)
        assert checks[case.expected_failure_stage]["accepted"] is False


def test_pretty_resigned_is_crypto_valid_but_not_szl_canonical_profile(bundle):
    case = _case(bundle, "pretty_json_resigned")
    result = benchmark.verify_profile(case.envelope, case.verification_key_pem)
    assert result["accepted"] is False
    assert result["reason"] == "payload-not-canonical-json"
    assert benchmark.verify_raw_signature(case.envelope, case.verification_key_pem)["accepted"] is True


def test_unsigned_and_advisory_digest_are_distinct_failures(bundle):
    unsigned = _case(bundle, "unsigned")
    advisory = _case(bundle, "advisory_digest_tamper")
    assert benchmark.verify_profile(unsigned.envelope, unsigned.verification_key_pem)["reason"] == "unsigned-honest"
    assert benchmark.verify_profile(advisory.envelope, advisory.verification_key_pem)["reason"] == "digest-mismatch"
    assert benchmark.verify_raw_signature(advisory.envelope, advisory.verification_key_pem)["accepted"] is True


@pytest.mark.parametrize("field,value,failed_check", [
    ("artifact_sha256", "0" * 64, "artifact_binding"),
    ("artifact_name", "different-artifact.txt", "artifact_binding"),
    ("source_repository", "https://github.com/szl-holdings/different-source", "source_binding"),
    ("source_revision", "1" * 40, "source_binding"),
    ("predicate_type", "https://a-11-oy.com/attest/different-fixture/v1", "source_binding"),
    ("admitted_public_key_sha256", (), "fixture_signer_policy"),
])
def test_frozen_policy_mutants_deny_valid_signed_fixture(bundle, field, value, failed_check):
    valid = _case(bundle, "valid")
    mutant = dataclasses.replace(bundle.policy, **{field: value})
    assert benchmark.verify_raw_signature(valid.envelope, valid.verification_key_pem)["accepted"] is True
    checks = benchmark.verify_fixture_policy(valid.envelope, valid.verification_key_pem, bundle.artifact, mutant)
    assert checks[failed_check]["accepted"] is False
    assert benchmark.sha256(benchmark.canonical_json(mutant.as_dict())) != benchmark.sha256(benchmark.canonical_json(bundle.policy.as_dict()))


def test_keyid_cannot_admit_second_signer(bundle):
    second = _case(bundle, "valid_signer_not_admitted")
    envelope = copy.deepcopy(second.envelope)
    envelope["keyid"] = bundle.policy.admitted_public_key_sha256[0]
    assert benchmark.verify_raw_signature(envelope, second.verification_key_pem)["accepted"] is True
    result = benchmark.verify_fixture_policy(envelope, second.verification_key_pem, bundle.artifact, bundle.policy)
    assert result["fixture_signer_policy"]["accepted"] is False
    assert result["fixture_signer_policy"]["keyid_considered"] is False


def test_target_artifact_bytes_really_hashed(bundle):
    valid = _case(bundle, "valid")
    altered_artifact = bundle.artifact + b"tampered target bytes"
    result = benchmark.verify_fixture_policy(valid.envelope, valid.verification_key_pem, altered_artifact, bundle.policy)
    assert result["artifact_binding"]["accepted"] is False
    assert result["artifact_binding"]["target_bytes_sha256"] == benchmark.sha256(altered_artifact)
    assert result["source_binding"]["accepted"] is True
    assert result["fixture_signer_policy"]["accepted"] is True


def test_frozen_policy_immutable(bundle):
    with pytest.raises(dataclasses.FrozenInstanceError):
        bundle.policy.source_revision = "0" * 40


def test_full_report_uses_public_fixture_bytes_only(bundle, openssl):
    report, code = benchmark.run_benchmark(openssl.executable or "nonexistent-szl-verifier-command", True, bundle)
    assert report["summary"]["mismatch_count"] == 0, report["mismatches"]
    assert code == (0 if openssl.available else 2)
    assert report["summary"]["all_expected_verdicts_measured"] is openssl.available
    assert report["summary"]["production_authorization"] == "BLOCKED"
    assert report["boundary"]["key_trust"] == "REPO_DECLARED"
    assert report["boundary"]["independent_external_replay"] == "NOT RUN"
    assert report["boundary"]["source_correctness"] == "UNKNOWN"
    assert report["fixture_manifest_sha256"] == benchmark.sha256(benchmark.canonical_json(report["fixture_manifest"]))
    manifest = report["fixture_manifest"]
    assert base64.b64decode(manifest["artifact_base64"]) == bundle.artifact
    assert manifest["policy_sha256"] == benchmark.sha256(benchmark.canonical_json(bundle.policy.as_dict()))
    serialized = json.dumps(report)
    assert "PRIVATE KEY" not in serialized
    assert len(report["source"]["function_source_sha256"]) >= 8
    assert report["runtime"]["cryptography"]


def test_strict_absent_adapter_is_unavailable_not_pass(bundle):
    report, code = benchmark.run_benchmark("nonexistent-szl-verifier-command", True, bundle)
    assert code == 2
    assert report["comparison_evidence_class"] == "UNAVAILABLE"
    assert report["summary"]["all_expected_verdicts_measured"] is False
    assert report["summary"]["external_comparison_complete"] is False
    assert all(row["checks"]["openssl"]["accepted"] is None for row in report["results"])
    assert all(row["raw_signature_agreement"] is None for row in report["results"])


def test_optional_absent_adapter_has_no_success_claim(bundle):
    report, code = benchmark.run_benchmark("nonexistent-szl-verifier-command", False, bundle)
    assert code == 0
    assert report["comparison_evidence_class"] == "UNAVAILABLE"
    assert report["summary"]["all_expected_verdicts_measured"] is False


def test_mutated_expected_verdict_cannot_pass(bundle, openssl):
    valid = bundle.cases[0]
    expected = {**valid.expected, "artifact_binding": False}
    mutant = dataclasses.replace(bundle, cases=(dataclasses.replace(valid, expected=expected),))
    report, code = benchmark.run_benchmark(openssl.executable or "nonexistent-szl-verifier-command", False, mutant)
    assert code == 1
    assert report["comparison_evidence_class"] == "BLOCKED"
    assert {"case": "valid", "adapter": "artifact_binding", "expected": False, "observed": True} in report["mismatches"]


def test_cli_absent_required_and_explicit_output(fixture_directory):
    receipt = fixture_directory / "receipt.json"
    process = subprocess.run([sys.executable, "-B", str(ROOT / "conformance/benchmark_verifiers.py"),
                              "--openssl", "nonexistent-szl-verifier-command", "--require-openssl",
                              "--output", str(receipt)], capture_output=True, text=True, timeout=30, check=False)
    assert process.returncode == 2, process.stderr
    report = json.loads(receipt.read_text(encoding="utf-8"))
    printed = json.loads(process.stdout)
    assert printed["receipt_sha256"] == benchmark.sha256(receipt.read_bytes())
    assert receipt.read_bytes().endswith(b"\n")
    assert report["comparison_evidence_class"] == "UNAVAILABLE"
    assert report["invocation"]["receipt_write"] == "explicit --output"
    assert list(fixture_directory.iterdir()) == [receipt]


def test_cli_stdout_default_creates_no_receipt(fixture_directory):
    process = subprocess.run([sys.executable, "-B", str(ROOT / "conformance/benchmark_verifiers.py"),
                              "--openssl", "nonexistent-szl-verifier-command", "--require-openssl"],
                             cwd=fixture_directory, capture_output=True, text=True, timeout=30, check=False)
    assert process.returncode == 2, process.stderr
    report = json.loads(process.stdout)
    assert report["invocation"]["receipt_write"] == "NOT RUN"
    assert list(fixture_directory.iterdir()) == []
