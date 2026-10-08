# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 SZL Contributors
"""Local exact-byte signature comparison on SAMPLE fixtures; no external effects.

This is an original SZL fixture policy, not general DSSE/in-toto/SLSA or cosign
qualification. Private fixture keys exist only in memory. OpenSSL receives only
public keys, public signatures and the exact production PAE bytes. No layout
inspection, network, provider, model or production authorization is exercised.
"""
from __future__ import annotations

import argparse
import base64
import copy
import dataclasses
import hashlib
import importlib.metadata
import inspect
import json
import platform
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from szl_receipt._canonical import canonical_json, pae
from szl_receipt._sign import PAYLOAD_TYPE, generate_keypair, sign_dsse, verify_dsse
from szl_receipt.attest import build_statement, verify_statement
from szl_receipt.receipt import Receipt, sign_receipt, verify_receipt


SCHEMA = "szl.receipt-cross-verifier-benchmark/v1"
PREDICATE_TYPE = "https://a-11-oy.com/attest/fixture-source-binding/v1"
SOURCE_REPOSITORY = "https://github.com/szl-holdings/szl-receipt"
SOURCE_REVISION = "1467fcbd1ff57b955d588c73e64a541ebc16770f"
ARTIFACT_NAME = "sample-artifact.txt"
ARTIFACT_BYTES = b"SZL receipt verifier SAMPLE artifact\nNo production authority.\n"
MAX_OUTPUT = 2048
TIMEOUT_SECONDS = 10
EXPECTED_FIELDS = (
    "cryptography", "receipt_profile", "artifact_binding", "source_binding",
    "fixture_signer_policy", "fixture_admitted",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bounded(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value[:MAX_OUTPUT]


def _result(accepted: bool | None, stage: str, reason: str, **extra: Any) -> dict:
    return {
        "evidence_class": "UNAVAILABLE" if accepted is None else "MEASURED",
        "accepted": accepted,
        "failure_stage": None if accepted is True else stage,
        "reason": _bounded(reason),
        **extra,
    }


def public_key_fingerprint(public_key_pem: bytes) -> str:
    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("fixture verifier requires an ECDSA P-256 public key")
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return sha256(der)


@dataclasses.dataclass(frozen=True)
class FixturePolicy:
    """Frozen local expectations; fingerprints are fixture admission, not trust."""

    artifact_sha256: str
    source_repository: str
    source_revision: str
    admitted_public_key_sha256: tuple[str, ...]
    predicate_type: str = PREDICATE_TYPE
    artifact_name: str = ARTIFACT_NAME

    def as_dict(self) -> dict:
        return {
            "schema": "szl.fixture-verification-policy/v1",
            "evidence_class": "SAMPLE",
            "artifact_sha256": self.artifact_sha256,
            "artifact_name": self.artifact_name,
            "source_repository": self.source_repository,
            "source_revision": self.source_revision,
            "predicate_type": self.predicate_type,
            "admitted_public_key_sha256": list(self.admitted_public_key_sha256),
            "fingerprint_domain": "SHA256(SubjectPublicKeyInfo DER)",
            "keyid_grants_authority": False,
            "key_trust": "REPO_DECLARED",
            "production_authorization": "BLOCKED",
        }


@dataclasses.dataclass(frozen=True)
class FixtureCase:
    name: str
    envelope: dict
    verification_key_pem: bytes
    expected: dict[str, bool]
    expected_failure_stage: str | None


@dataclasses.dataclass(frozen=True)
class FixtureBundle:
    artifact: bytes
    policy: FixturePolicy
    cases: tuple[FixtureCase, ...]


def _expected(crypto: bool = True, profile: bool = True, artifact: bool = True,
              source: bool = True, signer: bool = True) -> dict[str, bool]:
    return dict(zip(EXPECTED_FIELDS, (
        crypto, profile, artifact, source, signer,
        crypto and profile and artifact and source and signer,
    )))


def build_fixture_bundle() -> FixtureBundle:
    """Generate the complete public fixture set before any verifier is called."""
    private_one, public_one = generate_keypair()
    private_two, public_two = generate_keypair()
    policy = FixturePolicy(
        sha256(ARTIFACT_BYTES), SOURCE_REPOSITORY, SOURCE_REVISION,
        (public_key_fingerprint(public_one),),
    )
    statement = build_statement(
        subject_name=ARTIFACT_NAME,
        subject_digest=policy.artifact_sha256,
        predicate_type=PREDICATE_TYPE,
        predicate={
            "fixture_class": "SAMPLE",
            "source": {"repository": SOURCE_REPOSITORY, "revision": SOURCE_REVISION},
            "sample_note": "original SZL fixture; source label is not provenance validation",
        },
    )

    def sign(body: dict, key: bytes = private_one) -> dict:
        return sign_receipt(Receipt("sample-fixture", body), key, organ="SAMPLE", keyid="admitted-fixture-hint")

    valid = sign(statement)
    cases = [FixtureCase("valid", valid, public_one, _expected(), None)]

    tampered = copy.deepcopy(statement)
    tampered["predicate"]["sample_note"] = "modified without replacing signature"
    envelope = copy.deepcopy(valid)
    envelope["payload"] = base64.b64encode(canonical_json(tampered)).decode("ascii")
    cases.append(FixtureCase("payload_tamper", envelope, public_one, _expected(False, False), "cryptography"))

    envelope = copy.deepcopy(valid)
    envelope["payloadType"] = "application/vnd.szl.receipt+tampered"
    cases.append(FixtureCase("payload_type_tamper", envelope, public_one, _expected(False, False), "cryptography"))

    envelope = copy.deepcopy(valid)
    signature = bytearray(base64.b64decode(envelope["signature"], validate=True))
    signature[-1] ^= 1
    envelope["signature"] = base64.b64encode(signature).decode("ascii")
    cases.append(FixtureCase("signature_tamper", envelope, public_one, _expected(False, False), "cryptography"))
    cases.append(FixtureCase("wrong_verification_key", copy.deepcopy(valid), public_two,
                             _expected(False, False, signer=False), "cryptography"))

    pretty = json.dumps(statement, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8")
    envelope = copy.deepcopy(valid)
    envelope["payload"] = base64.b64encode(pretty).decode("ascii")
    cases.append(FixtureCase("pretty_json_unchanged_signature", envelope, public_one,
                             _expected(False, False), "cryptography"))
    envelope = copy.deepcopy(envelope)
    # This serialization control intentionally bypasses canonical signing, using
    # maintained cryptography with the unchanged production PAE implementation.
    private_key = serialization.load_pem_private_key(private_one, password=None)
    envelope["signature"] = base64.b64encode(
        private_key.sign(pae(PAYLOAD_TYPE, pretty), ec.ECDSA(hashes.SHA256()))
    ).decode("ascii")
    cases.append(FixtureCase("pretty_json_resigned", envelope, public_one,
                             _expected(profile=False), "receipt_profile"))

    envelope = copy.deepcopy(valid)
    envelope["digest"] = "0" * 64
    cases.append(FixtureCase("advisory_digest_tamper", envelope, public_one,
                             _expected(profile=False), "receipt_profile"))
    envelope = sign_receipt(Receipt("sample-fixture", statement), None, organ="SAMPLE")
    cases.append(FixtureCase("unsigned", envelope, public_one, _expected(False, False), "cryptography"))

    wrong_artifact = copy.deepcopy(statement)
    wrong_artifact["subject"][0]["digest"]["sha256"] = sha256(b"a different SAMPLE artifact\n")
    cases.append(FixtureCase("signed_wrong_artifact", sign(wrong_artifact), public_one,
                             _expected(artifact=False), "artifact_binding"))
    # The spoofed admitted keyid cannot admit the second public key.
    cases.append(FixtureCase("valid_signer_not_admitted", sign(statement, private_two), public_two,
                             _expected(signer=False), "fixture_signer_policy"))
    wrong_source = copy.deepcopy(statement)
    wrong_source["predicate"]["source"]["revision"] = "0" * 40
    cases.append(FixtureCase("signed_wrong_source_revision", sign(wrong_source), public_one,
                             _expected(source=False), "source_binding"))
    # Do not return any private key, private-key hash or private-key encoding.
    return FixtureBundle(ARTIFACT_BYTES, policy, tuple(cases))


def _decode(envelope: dict) -> tuple[bytes, bytes, bytes]:
    payload_type = envelope["payloadType"]
    if not isinstance(payload_type, str):
        raise ValueError("payload type must be a string")
    payload = base64.b64decode(envelope["payload"], validate=True)
    signature = base64.b64decode(envelope["signature"], validate=True)
    return payload, signature, pae(payload_type, payload)


def verify_raw_signature(envelope: dict, public_key_pem: bytes) -> dict:
    """Authenticate exact decoded payload PAE, without canonical reserialization."""
    try:
        _, signature, signing_bytes = _decode(envelope)
        key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            return _result(False, "cryptography", "verification key is not ECDSA P-256")
        key.verify(signature, signing_bytes, ec.ECDSA(hashes.SHA256()))
        return _result(True, "cryptography", "valid exact-byte ECDSA-P256/SHA256 signature")
    except InvalidSignature:
        return _result(False, "cryptography", "InvalidSignature")
    except (ValueError, TypeError, KeyError) as exc:
        return _result(False, "envelope_or_key", type(exc).__name__)
    except Exception as exc:
        return _result(None, "cryptography_adapter", type(exc).__name__)


def verify_profile(envelope: dict, public_key_pem: bytes) -> dict:
    try:
        accepted, reason = verify_receipt(envelope, public_key_pem)
        return _result(accepted, "receipt_profile", reason)
    except Exception as exc:
        return _result(None, "receipt_profile_adapter", type(exc).__name__)


def verify_fixture_policy(envelope: dict, public_key_pem: bytes, artifact: bytes,
                          policy: FixturePolicy) -> dict[str, dict]:
    """Independent local metadata comparisons; authentication is a separate gate."""
    observed_artifact_sha = sha256(artifact)
    try:
        payload, _, _ = _decode(envelope)
        statement = json.loads(payload.decode("utf-8"))
        artifact_ok, reason = verify_statement(
            statement, expected_digest=observed_artifact_sha, predicate_type=policy.predicate_type,
        )
        artifact_ok = artifact_ok and observed_artifact_sha == policy.artifact_sha256
        if observed_artifact_sha != policy.artifact_sha256:
            reason = "target-bytes-do-not-match-frozen-artifact-policy"
        elif artifact_ok and not any(
            s.get("name") == policy.artifact_name and s.get("digest", {}).get("sha256") == observed_artifact_sha
            for s in statement["subject"]
        ):
            artifact_ok, reason = False, "fixture-subject-name-not-bound"
        source = statement.get("predicate", {}).get("source", {})
        source_ok = (
            statement.get("predicateType") == policy.predicate_type
            and source.get("repository") == policy.source_repository
            and source.get("revision") == policy.source_revision
        )
        artifact_result = _result(artifact_ok, "artifact_binding", reason,
                                  target_bytes_sha256=observed_artifact_sha)
        source_result = _result(source_ok, "source_binding", "ok" if source_ok else "fixture-source-policy-mismatch")
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError) as exc:
        artifact_result = _result(False, "artifact_binding", type(exc).__name__,
                                  target_bytes_sha256=observed_artifact_sha)
        source_result = _result(False, "source_binding", type(exc).__name__)
    except Exception as exc:
        artifact_result = _result(None, "artifact_policy_adapter", type(exc).__name__)
        source_result = _result(None, "source_policy_adapter", type(exc).__name__)
    try:
        fingerprint = public_key_fingerprint(public_key_pem)
        signer_ok = fingerprint in policy.admitted_public_key_sha256
        signer_result = _result(signer_ok, "fixture_signer_policy",
                                "ok" if signer_ok else "public-key-not-admitted-by-frozen-fixture-policy",
                                public_key_sha256=fingerprint, keyid_considered=False)
    except (ValueError, TypeError) as exc:
        signer_result = _result(False, "fixture_signer_policy", type(exc).__name__)
    for result in (artifact_result, source_result, signer_result):
        result["authenticated_by_this_check"] = False
    return {"artifact_binding": artifact_result, "source_binding": source_result,
            "fixture_signer_policy": signer_result}


class OpenSSLVerifier:
    """Only OpenSSL version/dgst subprocesses; no private key file is created."""

    def __init__(self, executable: str | None = None, timeout: float = TIMEOUT_SECONDS):
        self.timeout = timeout
        self.executable: str | None = None
        self.version = "UNAVAILABLE"
        self.reason = "OpenSSL executable not found"
        self.discovery = "explicit" if executable is not None else "PATH_or_Git_for_Windows"
        candidate = shutil.which(executable) if executable is not None else shutil.which("openssl")
        if candidate is None and executable is None:
            bundled = Path("C:/Program Files/Git/usr/bin/openssl.exe")
            if bundled.is_file():
                candidate = str(bundled)
        self.version_command: dict = {"argv": []}
        if not candidate:
            return
        self.executable = str(Path(candidate).resolve())
        argv = [self.executable, "version"]
        self.version_command = {"argv": argv}
        try:
            process = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
            self.version_command.update(returncode=process.returncode,
                                         stdout=_bounded(process.stdout), stderr=_bounded(process.stderr))
            version = _bounded(process.stdout).strip()
            if process.returncode == 0 and version.startswith("OpenSSL "):
                self.version, self.reason = version, "ok"
            else:
                self.reason = "OpenSSL version probe failed"
        except subprocess.TimeoutExpired as exc:
            self.reason = "OpenSSL version probe timed out"
            self.version_command.update(stdout=_bounded(exc.stdout), stderr=_bounded(exc.stderr))
        except OSError as exc:
            self.reason = type(exc).__name__

    @property
    def available(self) -> bool:
        return self.version != "UNAVAILABLE"

    def metadata(self) -> dict:
        return {"evidence_class": "MEASURED" if self.available else "UNAVAILABLE",
                "version": self.version, "discovery": self.discovery,
                "reason": self.reason, "version_command": self.version_command,
                "executable_sha256": sha256(Path(self.executable).read_bytes()) if self.available else None}

    def verify(self, envelope: dict, public_key_pem: bytes) -> dict:
        if not self.available:
            return _result(None, "openssl_unavailable", self.reason)
        try:
            _, signature, signing_bytes = _decode(envelope)
        except (ValueError, TypeError, KeyError) as exc:
            return _result(False, "envelope", type(exc).__name__)
        # Public files only. The recorded relative argv is the exact executed
        # command; its working directory is an automatically removed fixture dir.
        with tempfile.TemporaryDirectory(prefix="szl-public-verifier-") as temporary:
            directory = Path(temporary)
            (directory / "public.pem").write_bytes(public_key_pem)
            (directory / "signature.der").write_bytes(signature)
            argv = [self.executable, "dgst", "-sha256", "-verify", "public.pem", "-signature", "signature.der"]
            command = {"argv": argv, "cwd_role": "removed_ephemeral_public_fixture_directory",
                       "stdin_sha256": sha256(signing_bytes),
                       "public_pem_sha256": sha256(public_key_pem), "signature_der_sha256": sha256(signature)}
            try:
                process = subprocess.run(argv, input=signing_bytes, capture_output=True,
                                         cwd=directory, timeout=self.timeout, check=False)
                command.update(returncode=process.returncode, stdout=_bounded(process.stdout), stderr=_bounded(process.stderr))
                combined = (command["stdout"] + "\n" + command["stderr"]).lower()
                if process.returncode == 0 and command["stdout"].strip() == "Verified OK":
                    return _result(True, "openssl_signature", "Verified OK", command=command)
                if not signature and process.returncode == 1 and "error reading signature file signature.der" in combined:
                    return _result(False, "openssl_unsigned", "OpenSSL rejected the empty signature file", command=command)
                if process.returncode == 1 and ("verification failure" in combined or "error verifying data" in combined):
                    return _result(False, "openssl_signature", "OpenSSL rejected the exact-byte signature", command=command)
                return _result(None, "openssl_adapter", "unexpected OpenSSL result", command=command)
            except subprocess.TimeoutExpired as exc:
                command.update(stdout=_bounded(exc.stdout), stderr=_bounded(exc.stderr))
                return _result(None, "openssl_timeout", "OpenSSL dgst timed out", command=command)
            except OSError as exc:
                return _result(None, "openssl_adapter", type(exc).__name__, command=command)


def _fixture_record(case: FixtureCase) -> dict:
    payload, signature, signing_bytes = _decode(case.envelope)
    return {"name": case.name, "evidence_class": "SAMPLE",
            "envelope": copy.deepcopy(case.envelope),
            "verification_public_key_pem": case.verification_key_pem.decode("ascii"),
            "expected": case.expected, "expected_failure_stage": case.expected_failure_stage,
            "hashes": {"envelope_canonical_json_sha256": sha256(canonical_json(case.envelope)),
                       "payload_sha256": sha256(payload), "pae_sha256": sha256(signing_bytes),
                       "signature_der_sha256": sha256(signature),
                       "verification_public_key_sha256": public_key_fingerprint(case.verification_key_pem)}}


def _source_metadata() -> dict:
    functions = (pae, canonical_json, sign_dsse, verify_dsse, sign_receipt, verify_receipt,
                 build_statement, verify_statement, verify_raw_signature, verify_fixture_policy)
    function_hashes = {}
    for function in functions:
        path = Path(inspect.getsourcefile(function)).resolve()
        # A preloaded installed package must not silently stand in for this tree.
        if ROOT not in path.parents:
            raise RuntimeError("benchmark did not load the assigned source tree")
        function_hashes[f"{function.__module__}.{function.__name__}"] = sha256(inspect.getsource(function).encode("utf-8"))
    paths = {Path(inspect.getsourcefile(function)).resolve() for function in functions}
    paths.add(Path(__file__).resolve())
    paths.add(ROOT / "src/szl_receipt/_intoto.py")
    files = {path.relative_to(ROOT).as_posix(): sha256(path.read_bytes()) for path in sorted(paths)}
    try:
        process = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, timeout=5, check=False)
        revision = process.stdout.decode("ascii").strip() if process.returncode == 0 else "UNKNOWN"
    except (OSError, subprocess.TimeoutExpired):
        revision = "UNKNOWN"
    try:
        process = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, timeout=5, check=False)
        working_tree_clean = not process.stdout if process.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        working_tree_clean = None
    return {"git_revision": revision, "working_tree_files_sha256": files,
            "working_tree_clean": working_tree_clean,
            "function_source_sha256": function_hashes,
            "source_correctness": "UNKNOWN", "source_hashes_are_not_release_authorization": True}


def run_benchmark(openssl: str | None = None, require_openssl: bool = False,
                  bundle: FixtureBundle | None = None) -> tuple[dict, int]:
    bundle = bundle or build_fixture_bundle()
    # Freeze policy and all fixture input bytes/hashes before adapter execution.
    policy_record = bundle.policy.as_dict()
    manifest = {"schema": "szl.public-verifier-fixtures/v1", "evidence_class": "SAMPLE",
                "artifact_base64": base64.b64encode(bundle.artifact).decode("ascii"),
                "artifact_sha256": sha256(bundle.artifact), "policy": policy_record,
                "policy_sha256": sha256(canonical_json(policy_record)),
                "cases": [_fixture_record(case) for case in bundle.cases]}
    frozen_manifest_bytes = canonical_json(manifest)
    verifier = OpenSSLVerifier(openssl)
    results, mismatches = [], []
    for case in bundle.cases:
        actual = {"cryptography": verify_raw_signature(case.envelope, case.verification_key_pem),
                  "receipt_profile": verify_profile(case.envelope, case.verification_key_pem),
                  "openssl": verifier.verify(case.envelope, case.verification_key_pem),
                  **verify_fixture_policy(case.envelope, case.verification_key_pem, bundle.artifact, bundle.policy)}
        states = [actual[field]["accepted"] for field in EXPECTED_FIELDS[:-1]]
        unavailable = any(state is None for state in states)
        accepted = None if unavailable else all(states)
        first_failure = next((field for field in EXPECTED_FIELDS[:-1] if actual[field]["accepted"] is not True), None)
        actual["fixture_admitted"] = _result(accepted, first_failure or "fixture_policy", "ok" if accepted else "fixture gate denied or unavailable")
        for field in EXPECTED_FIELDS:
            if actual[field]["accepted"] != case.expected[field]:
                mismatches.append({"case": case.name, "adapter": field,
                                   "expected": case.expected[field], "observed": actual[field]["accepted"]})
        if first_failure != case.expected_failure_stage:
            mismatches.append({"case": case.name, "adapter": "first_failure_stage",
                               "expected": case.expected_failure_stage, "observed": first_failure})
        external = actual["openssl"]["accepted"]
        if verifier.available and external != case.expected["cryptography"]:
            mismatches.append({"case": case.name, "adapter": "openssl",
                               "expected": case.expected["cryptography"], "observed": external})
        results.append({"case": case.name, "input_evidence_class": "SAMPLE", "expected": case.expected,
                        "checks": actual, "first_failure_stage": first_failure,
                        "raw_signature_agreement": external == actual["cryptography"]["accepted"] if external is not None else None,
                        "production_authorization": "BLOCKED"})
    # Mutation during verification is a benchmark failure, even if verdicts fit.
    if frozen_manifest_bytes != canonical_json({**manifest, "policy": bundle.policy.as_dict(),
                                                "cases": [_fixture_record(case) for case in bundle.cases]}):
        mismatches.append({"case": "fixture_manifest", "adapter": "frozen-input-check", "expected": "unchanged", "observed": "changed"})
    external_complete = verifier.available and all(r["checks"]["openssl"]["accepted"] is not None for r in results)
    comparison_class = "BLOCKED" if mismatches else "MEASURED" if external_complete else "UNAVAILABLE"
    exit_code = 1 if mismatches else 2 if require_openssl and not external_complete else 0
    report = {
        "schema": SCHEMA, "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "input_evidence_class": "SAMPLE", "comparison_evidence_class": comparison_class,
        "require_openssl": require_openssl,
        "summary": {"case_count": len(results), "mismatch_count": len(mismatches),
                    "external_comparison_complete": external_complete,
                    "all_expected_verdicts_measured": not mismatches and external_complete,
                    "production_authorization": "BLOCKED", "exit_code": exit_code},
        "boundary": {"profile": "SZL canonical receipt + original fixture policy",
                     "crypto_scope": "ECDSA-P256/SHA256 on exact decoded payload production PAE bytes",
                     "artifact_binding_scope": "SHA256(target SAMPLE artifact bytes) versus Statement subject and frozen policy",
                     "source_binding_scope": "DECLARED predicate source fields versus frozen local expectation",
                     "key_trust": "REPO_DECLARED", "source_correctness": "UNKNOWN",
                     "slsa_level": "UNKNOWN", "independent_external_replay": "NOT RUN",
                     "production_authorization": "BLOCKED", "external_effects": "NOT RUN",
                     "layout_inspections": "NOT RUN", "general_standard_conformance": "NOT RUN",
                     "adapter_diversity_does_not_establish_implementation_independence": True,
                     "ephemeral_keys_make_fixture_hashes_run_specific": True},
        "runtime": {"python": platform.python_version(),
                    "cryptography": importlib.metadata.version("cryptography"),
                    "cryptography_openssl_backend": default_backend().openssl_version_text(),
                    "in_toto_attestation": importlib.metadata.version("in-toto-attestation"),
                    "openssl": verifier.metadata()},
        "source": _source_metadata(), "fixture_manifest_sha256": sha256(frozen_manifest_bytes),
        "fixture_manifest": json.loads(frozen_manifest_bytes), "results": results, "mismatches": mismatches,
    }
    return report, exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", help="explicit OpenSSL executable; otherwise discover PATH or Git for Windows")
    parser.add_argument("--require-openssl", action="store_true", help="return nonzero if external comparison is unavailable")
    parser.add_argument("--output", type=Path, help="explicit receipt path; omitted means stdout only, no receipt file")
    args = parser.parse_args(argv)
    try:
        report, exit_code = run_benchmark(args.openssl, args.require_openssl)
    except Exception as exc:
        report, exit_code = {"schema": SCHEMA, "comparison_evidence_class": "BLOCKED",
                             "failure_stage": "benchmark_setup", "reason": type(exc).__name__,
                             "production_authorization": "BLOCKED"}, 1
    report["invocation"] = {"python_executable": sys.executable, "argv": list(sys.argv[1:] if argv is None else argv),
                            "receipt_write": "explicit --output" if args.output else "NOT RUN"}
    encoded = (json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    if args.output:
        try:
            # No implicit parent-directory creation or persistent private fixture.
            # Write exactly the serialized bytes being hashed; text mode would
            # translate LF to CRLF on Windows and invalidate the receipt digest.
            args.output.write_bytes(encoded)
        except OSError as exc:
            print(json.dumps({"schema": SCHEMA, "comparison_evidence_class": "BLOCKED",
                              "failure_stage": "explicit_receipt_write", "reason": type(exc).__name__,
                              "production_authorization": "BLOCKED"}))
            return 1
        print(json.dumps({"schema": SCHEMA, "comparison_evidence_class": report["comparison_evidence_class"],
                          "summary": report.get("summary"), "receipt_sha256": sha256(encoded),
                          "production_authorization": "BLOCKED"}))
    else:
        print(encoded.decode("utf-8"), end="")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
