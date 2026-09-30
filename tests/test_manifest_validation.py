"""Synthetic manifest evidence must fail closed before writing any output."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "emit_run_manifest.py"
VALID = {"pass_rate": 0.75, "heldout_passed": False, "refusal_no_regression": False}


def _emit(tmp_path, raw, *, existing=False):
    model = tmp_path / "synthetic-model"
    model.mkdir()
    evidence = tmp_path / "eval.json"
    evidence.write_bytes(raw)
    bom = tmp_path / "bom.json"
    bom.write_bytes(b'{"synthetic":true}\n')
    output = tmp_path / "release" / "manifest.json"
    if existing:
        output.parent.mkdir()
        output.write_bytes(b"historical evidence\n")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--model-dir", str(model),
         "--eval", str(evidence), "--bom", str(bom), "--git-sha", "a" * 40,
         "--workflow-run", "https://example.test/synthetic-run", "--out", str(output)],
        capture_output=True, text=True, timeout=10,
    )
    return result, output, bom


INVALID = [
    ("root-null", b"null"),
    ("root-list", b'["pass_rate","heldout_passed","refusal_no_regression"]'),
    ("root-string", b'"pass_rate heldout_passed refusal_no_regression"'),
    ("syntax", b"{"),
    ("invalid-utf8", b"\xff"),
    ("duplicate-verdict", b'{"pass_rate":1,"heldout_passed":false,'
     b'"heldout_passed":true,"refusal_no_regression":true}'),
]
for field in VALID:
    missing = dict(VALID)
    del missing[field]
    INVALID.append((f"missing-{field}", json.dumps(missing).encode()))
for field in ("heldout_passed", "refusal_no_regression"):
    for value in ("false", "true", "", 0, 1, None, [], [False], {}, {"pass": False}):
        INVALID.append((f"{field}-{value!r}", json.dumps({**VALID, field: value}).encode()))
for value in (True, False, "0.75", None, [], {}, -0.1, 1.1, 10**1000,
              float("nan"), float("inf"), -float("inf")):
    label = "huge-int" if isinstance(value, int) and value > 1 else repr(value)
    INVALID.append((f"rate-{label}", json.dumps({**VALID, "pass_rate": value}).encode()))
INVALID.append(("overflow-exponent", b'{"pass_rate":1e9999,"heldout_passed":true,'
                b'"refusal_no_regression":true}'))
INVALID.append(("supplemental-overflow", b'{"pass_rate":1,"heldout_passed":true,'
                b'"refusal_no_regression":true,"extra":{"rate":1e9999}}'))


@pytest.mark.parametrize("existing", [False, True], ids=["new", "preserve-history"])
@pytest.mark.parametrize("raw", [raw for _, raw in INVALID], ids=[label for label, _ in INVALID])
def test_invalid_evidence_fails_before_output(tmp_path, raw, existing):
    result, output, _ = _emit(tmp_path, raw, existing=existing)
    assert result.returncode == 1
    assert "::error::emit_run_manifest:" in result.stderr
    assert "Traceback" not in result.stderr
    if existing:
        assert output.read_bytes() == b"historical evidence\n"
    else:
        assert not output.exists()
        assert not output.parent.exists()


@pytest.mark.parametrize("rate", [0, 0.0, 0.75, 1, 1.0])
@pytest.mark.parametrize("heldout,refusal", [(False, False), (True, False),
                                           (False, True), (True, True)])
def test_valid_evidence_is_preserved_without_promoting_signature_or_conformance(
    tmp_path, rate, heldout, refusal,
):
    evidence = {"pass_rate": rate, "heldout_passed": heldout,
                "refusal_no_regression": refusal}
    result, output, bom = _emit(tmp_path, json.dumps(evidence).encode())
    assert result.returncode == 0, result.stderr
    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["eval"] == evidence
    assert manifest["eval"]["heldout_passed"] is heldout
    assert manifest["eval"]["refusal_no_regression"] is refusal
    assert manifest["signatures"]["manifest"] is False
    assert manifest["conformance"]["all_vectors_passed"] is False
    assert manifest["model_bom_sha256"] == hashlib.sha256(bom.read_bytes()).hexdigest()
