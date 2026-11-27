#!/usr/bin/env python3
"""Fail-closed admission for decontam verdict and red-team report digest.

Missing inputs, missing files, invalid JSON, a non-PASS/CLEAN verdict,
UNKNOWN, or a digest mismatch all fail the process. This script never
prints report bodies.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

PASS_VERDICTS = {"PASS", "CLEAN"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_FIELDS = (
    "train_set_digest",
    "dataset_digest",
    "train_set_sha256",
    "sha256",
)


def fail(message: str) -> None:
    print(f"::error::{message}", file=sys.stderr)
    raise SystemExit(1)


def load_verdict(path_text: str) -> dict:
    path = Path(path_text)
    if not path.is_file():
        fail(f"decontam verdict file is missing: {path_text}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("decontam verdict is not valid UTF-8 JSON; fails closed.")
    if not isinstance(data, dict):
        fail("decontam verdict must be a JSON object; fails closed.")
    verdict = data.get("verdict")
    if not isinstance(verdict, str) or verdict.strip().upper() not in PASS_VERDICTS:
        fail(
            "decontam verdict is "
            f"{verdict!r}; only PASS or CLEAN is admitted. "
            "UNKNOWN, FAIL, missing, or other values fail closed."
        )
    for key in DIGEST_FIELDS:
        value = data.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value.lower()):
            fail(f"decontam field {key} is not a sha256 hex digest; fails closed.")
    return data


def verify_redteam(digest: str, report_path: str) -> str:
    if not SHA256_RE.fullmatch(digest):
        fail("redteam_report_digest must be 64 lowercase hex characters; fails closed.")
    path = Path(report_path)
    if not path.is_file():
        fail(f"red-team report is missing: {report_path}")
    raw = path.read_bytes()
    if not raw:
        fail("red-team report is empty; fails closed.")
    actual = hashlib.sha256(raw).hexdigest()
    if actual != digest:
        fail("red-team report sha256 does not match redteam_report_digest; fails closed.")
    return actual


def admit(verdict_path: str, digest: str, report_path: str, out_path: Path) -> dict:
    if not verdict_path.strip():
        fail("decontam_verdict input is missing; publication gate fails closed.")
    if not digest.strip():
        fail("redteam_report_digest input is missing; publication gate fails closed.")
    if not report_path.strip():
        fail("redteam_report_path input is missing; publication gate fails closed.")
    data = load_verdict(verdict_path.strip())
    actual = verify_redteam(digest.strip().lower(), report_path.strip())
    result = {
        "decontam_passed": True,
        "decontam_verdict": data["verdict"].strip().upper(),
        "decontam_path": verdict_path.strip(),
        "redteam_digest_verified": True,
        "redteam_report_digest": actual,
        "redteam_report_path": report_path.strip(),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("evidence-admission PASS")
    for key, value in result.items():
        print(f"  {key}={value}")
    return result


def self_check() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        verdict = root / "contamination_verdict.json"
        report = root / "redteam-report.md"
        out = root / "evidence-admission.json"
        report.write_text("red-team report body\n", encoding="utf-8")
        digest = hashlib.sha256(report.read_bytes()).hexdigest()
        train = "a" * 64
        verdict.write_text(
            json.dumps({"verdict": "PASS", "train_set_digest": train}),
            encoding="utf-8",
        )
        admit(str(verdict), digest, str(report), out)
        assert json.loads(out.read_text())["decontam_passed"] is True

        # missing input
        try:
            admit("", digest, str(report), out)
        except SystemExit:
            pass
        else:
            raise AssertionError("empty decontam path must fail closed")

        # UNKNOWN verdict
        verdict.write_text(json.dumps({"verdict": "UNKNOWN"}), encoding="utf-8")
        try:
            admit(str(verdict), digest, str(report), out)
        except SystemExit:
            pass
        else:
            raise AssertionError("UNKNOWN verdict must fail closed")

        # digest mismatch
        verdict.write_text(json.dumps({"verdict": "CLEAN"}), encoding="utf-8")
        try:
            admit(str(verdict), "b" * 64, str(report), out)
        except SystemExit:
            pass
        else:
            raise AssertionError("digest mismatch must fail closed")

        # missing report
        try:
            admit(str(verdict), digest, str(root / "missing.md"), out)
        except SystemExit:
            pass
        else:
            raise AssertionError("missing report must fail closed")

    print("self-check PASS")


def main() -> None:
    if "--self-check" in sys.argv:
        self_check()
        return
    admit(
        os.environ.get("DECONTAM_VERDICT", ""),
        os.environ.get("REDTEAM_DIGEST", ""),
        os.environ.get("REDTEAM_PATH", ""),
        Path(os.environ.get("EVIDENCE_OUT", "release/evidence-admission.json")),
    )


if __name__ == "__main__":
    main()
