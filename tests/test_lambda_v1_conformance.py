# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 SZL Contributors
"""szl.lambda/v1 conformance for the strictest Λ copy, ``src/szl_receipt/lambda_gate.py``.

FF-03 (finding E5: divergent Λ copies). The golden vectors are vendored byte for
byte from szl-holdings/szl-lambda-gate at the FF-01 merge commit.
``tests/fixtures/lambda_v1_vectors.SOURCE`` records that commit and the
canonical-JSON SHA-256, and this file checks both.

How the copy is driven:

* ``lambda_gate.py`` is loaded **by file path**. The package ``__init__``, which
  imports ``in_toto_attestation``, is never imported. The module itself is
  stdlib-only.
* The vectors hold sequences, but this copy takes Mappings. ``axes[i]`` and
  ``weights[i]`` are fed as ``{"axis_<i>": value}``. A JSON value that is not a
  list is passed through unchanged, as the vectors file says.
* ``LambdaGateError`` maps to BLOCK. Its message is classified into the v1 error
  code it corresponds to. The copy compares key sets rather than lengths, so its
  ``axis mismatch`` has no v1 code and stays ``AXIS_MISMATCH``. Any other
  exception is a crash, and the test fails.
* ``advisory-pass`` maps to GO. ``advisory-fail`` maps to NO_GO, with the code
  ZERO_VETO when Λ == 0.0 and BELOW_TAU otherwise. The copy has no ABSTAIN.

A vector either conforms or is pinned. To conform, error codes and verdicts must
match exactly, and Λ must be within the vector's ``value_tol``. A pinned vector
is listed in ``KNOWN_DIVERGENCE``, and today's output is asserted exactly. There
is no xfail and no skip. When the copy changes, this file fails, and the slice
that aligns the copy edits the table. ``lambda_gate.py`` is not edited here.

Λ is advisory. Λ uniqueness is Conjecture 1 (open), and nothing here depends on it.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import re
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Tuple

import pytest

REPO = Path(__file__).resolve().parents[1]
LAMBDA_GATE_PATH = REPO / "src" / "szl_receipt" / "lambda_gate.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
VECTORS_PATH = FIXTURES / "lambda_v1_vectors.json"
SOURCE_PATH = FIXTURES / "lambda_v1_vectors.SOURCE"

#: The szl-lambda-gate merge commit of FF-01 (PR #53), which the fixture is copied from.
FF01_MERGE_SHA = "6a874e11ab948a47e982be3651b8021ba6b82e19"
#: spec/szl.lambda.v1.json#/vectors/sha256 at FF01_MERGE_SHA: the SHA-256 over canonical JSON.
VECTORS_CANONICAL_SHA256 = "61bfb0410b9f0eaab0eb9f22f29cb7cb13cfde8c083fe308d895565d6ba9ebd4"
#: spec/szl.lambda.v1.json#/vectors/count at FF01_MERGE_SHA.
VECTORS_COUNT = 60
#: spec/szl.lambda.v1.json#/weight_sum_tol at FF01_MERGE_SHA. The spec is not vendored; this value is.
V1_WEIGHT_SUM_TOL = 1e-12

V1_ERROR_CODES = (
    "LAMBDA_TYPE_INVALID",
    "LAMBDA_EMPTY",
    "LAMBDA_LENGTH_MISMATCH",
    "LAMBDA_NONFINITE_AXIS",
    "LAMBDA_AXIS_OUT_OF_RANGE",
    "LAMBDA_NONFINITE_WEIGHT",
    "LAMBDA_WEIGHT_NONPOSITIVE",
    "LAMBDA_WEIGHT_SUM",
    "LAMBDA_TAU_INVALID",
)
V1_VERDICTS = ("GO", "NO_GO", "ABSTAIN", "BLOCK")

#: The copy's own code for a key-set mismatch. It is not a v1 code.
AXIS_MISMATCH = "AXIS_MISMATCH"


# --------------------------------------------------------------- the copy, by path --

_MODULE_NAME = "_ff03_szl_receipt_lambda_gate_by_path"


def _load_lambda_gate_by_path():
    spec = importlib.util.spec_from_file_location(_MODULE_NAME, LAMBDA_GATE_PATH)
    assert spec is not None and spec.loader is not None, LAMBDA_GATE_PATH
    module = importlib.util.module_from_spec(spec)
    # @dataclass resolves string annotations through sys.modules[cls.__module__].
    sys.modules[_MODULE_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(_MODULE_NAME, None)
        raise
    return module


LG = _load_lambda_gate_by_path()


# --------------------------------------------------------------------- the vectors --


def _decode(value: Any) -> Any:
    """Decode ``f64:<16 hex>`` to its float, bit for bit. Pass any other JSON value through unchanged."""
    if isinstance(value, str) and value.startswith("f64:"):
        digits = value[4:]
        if len(digits) != 16 or any(c not in "0123456789abcdef" for c in digits):
            raise ValueError(f"malformed f64 literal: {value!r}")
        return struct.unpack(">d", bytes.fromhex(digits))[0]
    return value


def _canonical_sha256(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    ).hexdigest()


def _load_vectors() -> Dict[str, Any]:
    return json.loads(VECTORS_PATH.read_bytes().decode("utf-8"))


def _read_source() -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for raw in SOURCE_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition(":")
        assert sep, f"malformed .SOURCE line: {raw!r}"
        key = key.strip()
        assert key not in fields, f"duplicate .SOURCE key: {key}"
        fields[key] = value.strip()
    return fields


VECTORS: List[Dict[str, Any]] = _load_vectors()["vectors"]
VECTOR_IDS = [v["id"] for v in VECTORS]
BY_ID = {v["id"]: v for v in VECTORS}


# ---------------------------------------------------------------- the adapter --


def axis_name(index: int) -> str:
    return f"axis_{index}"


def as_axis_mapping(values: Any) -> Any:
    """Turn a vector's list into an index-to-axis-name Mapping. Pass any other value through unchanged."""
    if isinstance(values, list):
        return {axis_name(i): _decode(v) for i, v in enumerate(values)}
    return _decode(values)


#: Classifies a LambdaGateError message. Each pattern is matched at the start of the message.
_MESSAGE_CODES = (
    (re.compile(r"scores and weights must be mappings\Z"), "LAMBDA_TYPE_INVALID"),
    (re.compile(r"scores and weights must both be non-empty\Z"), "LAMBDA_EMPTY"),
    (re.compile(r"axis mismatch: "), AXIS_MISMATCH),
    (re.compile(r"(score|weight) for '[^']*' is not a real number: "), "LAMBDA_TYPE_INVALID"),
    (re.compile(r"score for '[^']*' is not finite: "), "LAMBDA_NONFINITE_AXIS"),
    (re.compile(r"score for '[^']*' must be in \[0,1\] \(got "), "LAMBDA_AXIS_OUT_OF_RANGE"),
    (re.compile(r"weight for '[^']*' is not finite: "), "LAMBDA_NONFINITE_WEIGHT"),
    (re.compile(r"weight for '[^']*' must be > 0 \(got "), "LAMBDA_WEIGHT_NONPOSITIVE"),
    (re.compile(r"weights must sum to 1 \(got "), "LAMBDA_WEIGHT_SUM"),
    (
        re.compile(r"theta (is not a real number: |is not finite: |must be in \(0,1\] \(got )"),
        "LAMBDA_TAU_INVALID",
    ),
)


def classify(message: str) -> str:
    """Return the error code for a LambdaGateError message. An unknown message fails loudly."""
    codes = [code for pattern, code in _MESSAGE_CODES if pattern.match(message)]
    assert len(codes) == 1, (
        f"unclassified LambdaGateError message (the copy changed its error surface): {message!r}"
    )
    return codes[0]


LamOutcome = Tuple[str, Any]  # ("value", float or f64 literal) | ("error", code)
GateOutcome = Tuple[str, Optional[str]]  # (verdict, code)

_GATE_VERDICTS = {"advisory-pass": "GO", "advisory-fail": "NO_GO"}


def observe_lambda(axes: Any, weights: Any) -> LamOutcome:
    try:
        return ("value", LG.lambda_score(as_axis_mapping(axes), as_axis_mapping(weights)))
    except LG.LambdaGateError as err:
        return ("error", classify(str(err)))


def observe_gate(axes: Any, weights: Any, tau: Any) -> GateOutcome:
    try:
        verdict = LG.evaluate(as_axis_mapping(axes), as_axis_mapping(weights), _decode(tau))
    except LG.LambdaGateError as err:
        return ("BLOCK", classify(str(err)))
    assert verdict.verdict in _GATE_VERDICTS, f"unknown verdict from the copy: {verdict.verdict!r}"
    if _GATE_VERDICTS[verdict.verdict] == "GO":
        return ("GO", None)
    return ("NO_GO", "ZERO_VETO" if verdict.lam == 0.0 else "BELOW_TAU")


def v1_lambda(vector: Dict[str, Any]) -> LamOutcome:
    expect = vector["expect"]
    if "error" in expect:
        return ("error", expect["error"])
    return ("value", expect["value_f64"])


def v1_gate(vector: Dict[str, Any]) -> GateOutcome:
    return (vector["expect"]["verdict"], vector["expect"]["code"])


def lam_equal(a: LamOutcome, b: LamOutcome, tol: float) -> bool:
    """Error codes compare exactly. Values compare within ``tol``, and both must be finite."""
    if a[0] != b[0]:
        return False
    if a[0] == "error":
        return a[1] == b[1]
    x, y = float(_decode(a[1])), float(_decode(b[1]))
    return math.isfinite(x) and math.isfinite(y) and abs(x - y) <= tol


# ------------------------------------------------------- the pinned divergences --

#: Weight-sum tolerance: 1e-9 in this copy, 1e-12 in v1.
WEIGHT_SUM_TOL_KIND = "WEIGHT_SUM_TOL_1E-9"
#: No tie band. The gate is ``lam >= theta``, so there is no ABSTAIN.
NO_TIE_BAND_KIND = "NO_TIE_BAND"
#: The copy compares key sets, so a length mismatch is reported as an axis mismatch.
AXIS_MISMATCH_KIND = "LENGTH_MISMATCH_AS_AXIS_MISMATCH"
#: The copy checks weights before scores, element by element. v1 checks in phases, axes first.
CHECK_ORDER_KIND = "CHECK_ORDER"

DIVERGENCE_KINDS = (
    WEIGHT_SUM_TOL_KIND,
    NO_TIE_BAND_KIND,
    AXIS_MISMATCH_KIND,
    CHECK_ORDER_KIND,
)


class Divergence(NamedTuple):
    """Today's output of the copy on one vector, where it differs from v1.

    ``lam`` and ``gate`` are the copy's outcomes for ``lambda_score`` and
    ``evaluate``. ``None`` means that half conforms to v1 and is checked against
    the vector.
    """

    eid: str
    kind: str
    lam: Optional[LamOutcome]
    gate: Optional[GateOutcome]


KNOWN_DIVERGENCE: Dict[str, Divergence] = {
    # |sum(w) - 1| = 3e-12 is inside this copy's 1e-9, so Λ is computed rather than blocked.
    # The value is the copy's output (0.6708203932497249), compared within value_tol.
    "weight_sum_outside_tol": Divergence(
        "E5", WEIGHT_SUM_TOL_KIND, ("value", "f64:3fe5775c544feaed"), ("NO_GO", "BELOW_TAU")
    ),
    # lam >= theta with no band: a Λ within 1e-9 of τ is GO or NO_GO, never ABSTAIN.
    "tie_exact": Divergence("E5", NO_TIE_BAND_KIND, None, ("GO", None)),
    "tie_inside_above": Divergence("E5", NO_TIE_BAND_KIND, None, ("GO", None)),
    "tie_inside_below": Divergence("E5", NO_TIE_BAND_KIND, None, ("NO_GO", "BELOW_TAU")),
    "tie_multi_axis_at_own_value": Divergence("E5", NO_TIE_BAND_KIND, None, ("GO", None)),
    # set(scores) != set(weights), reported before any length or type reasoning.
    "e5_dropped_axis_renormalised": Divergence(
        "E5", AXIS_MISMATCH_KIND, ("error", AXIS_MISMATCH), ("BLOCK", AXIS_MISMATCH)
    ),
    "length_mismatch_extra_weight": Divergence(
        "E5", AXIS_MISMATCH_KIND, ("error", AXIS_MISMATCH), ("BLOCK", AXIS_MISMATCH)
    ),
    # [1.5, nan]: the first score is range-checked before the second is finiteness-checked.
    "precedence_nonfinite_before_range_a": Divergence(
        "E5",
        CHECK_ORDER_KIND,
        ("error", "LAMBDA_AXIS_OUT_OF_RANGE"),
        ("BLOCK", "LAMBDA_AXIS_OUT_OF_RANGE"),
    ),
    # [1.5, 0.9] with w = [2, 2]: the weight sum is checked before any score.
    "precedence_axis_before_weight": Divergence(
        "E5", CHECK_ORDER_KIND, ("error", "LAMBDA_WEIGHT_SUM"), ("BLOCK", "LAMBDA_WEIGHT_SUM")
    ),
}


def expected_lambda(vector: Dict[str, Any]) -> LamOutcome:
    pinned = KNOWN_DIVERGENCE.get(vector["id"])
    if pinned is not None and pinned.lam is not None:
        return pinned.lam
    return v1_lambda(vector)


def expected_gate(vector: Dict[str, Any]) -> GateOutcome:
    pinned = KNOWN_DIVERGENCE.get(vector["id"])
    if pinned is not None and pinned.gate is not None:
        return pinned.gate
    return v1_gate(vector)


# ---------------------------------------------------------------------- tests --


@pytest.mark.parametrize("vector", VECTORS, ids=VECTOR_IDS)
def test_lambda_score_conforms_or_is_pinned(vector):
    observed = observe_lambda(vector["axes"], vector["weights"])
    expected = expected_lambda(vector)
    assert lam_equal(observed, expected, vector["value_tol"]), (
        f"{vector['id']}: lambda_score gave {observed}, expected {expected}"
    )


@pytest.mark.parametrize("vector", VECTORS, ids=VECTOR_IDS)
def test_evaluate_conforms_or_is_pinned(vector):
    observed = observe_gate(vector["axes"], vector["weights"], vector["tau"])
    assert observed == expected_gate(vector), f"{vector['id']}: evaluate gave {observed}"


def test_divergent_vectors_are_exactly_the_known_divergence_table():
    divergent = set()
    for vector in VECTORS:
        lam = observe_lambda(vector["axes"], vector["weights"])
        gate = observe_gate(vector["axes"], vector["weights"], vector["tau"])
        if not lam_equal(lam, v1_lambda(vector), vector["value_tol"]) or gate != v1_gate(vector):
            divergent.add(vector["id"])
    assert divergent == set(KNOWN_DIVERGENCE)


def test_every_pinned_half_really_diverges_from_v1():
    for vid, pinned in KNOWN_DIVERGENCE.items():
        vector = BY_ID[vid]
        assert pinned.eid == "E5" and pinned.kind in DIVERGENCE_KINDS, vid
        assert pinned.lam is not None or pinned.gate is not None, vid
        if pinned.lam is not None:
            assert not lam_equal(pinned.lam, v1_lambda(vector), vector["value_tol"]), vid
        if pinned.gate is not None:
            assert pinned.gate != v1_gate(vector), vid
    assert set(KNOWN_DIVERGENCE) <= set(VECTOR_IDS)
    assert {p.kind for p in KNOWN_DIVERGENCE.values()} == set(DIVERGENCE_KINDS)


def test_weight_sum_tolerance_divergence_is_1e9_against_1e12():
    assert LG.WEIGHT_SUM_TOL == 1e-9
    assert V1_WEIGHT_SUM_TOL == 1e-12
    inside = [_decode(w) for w in BY_ID["weight_sum_within_tol"]["weights"]]
    outside = [_decode(w) for w in BY_ID["weight_sum_outside_tol"]["weights"]]
    assert abs(math.fsum(inside) - 1.0) <= V1_WEIGHT_SUM_TOL
    # The outside vector falls between the two tolerances, and that is why it diverges.
    assert V1_WEIGHT_SUM_TOL < abs(math.fsum(outside) - 1.0) <= LG.WEIGHT_SUM_TOL
    assert KNOWN_DIVERGENCE["weight_sum_outside_tol"].kind == WEIGHT_SUM_TOL_KIND


def test_no_tie_band_the_copy_never_abstains():
    v1_ties = {v["id"] for v in VECTORS if v["expect"]["verdict"] == "ABSTAIN"}
    assert v1_ties, "the vectors must carry tie-band cases"
    for vid in v1_ties:
        vector = BY_ID[vid]
        assert KNOWN_DIVERGENCE[vid].kind == NO_TIE_BAND_KIND, vid
        verdict, _code = observe_gate(vector["axes"], vector["weights"], vector["tau"])
        assert verdict in ("GO", "NO_GO"), vid
    # A Λ exactly at theta passes (lam >= theta). v1 calls it a NUMERIC_TIE.
    assert LG.evaluate({"axis_0": 0.5}, {"axis_0": 1.0}, 0.5).verdict == "advisory-pass"


def test_length_mismatch_is_reported_as_axis_mismatch():
    length_rows = [v for v in VECTORS if v["expect"].get("error") == "LAMBDA_LENGTH_MISMATCH"]
    assert length_rows, "the vectors must carry length-mismatch cases"
    for vector in length_rows:
        with pytest.raises(LG.LambdaGateError, match=r"^axis mismatch: "):
            LG.lambda_score(as_axis_mapping(vector["axes"]), as_axis_mapping(vector["weights"]))
        assert KNOWN_DIVERGENCE[vector["id"]].kind == AXIS_MISMATCH_KIND


@pytest.mark.parametrize(
    "bad, code",
    [
        (float("nan"), "LAMBDA_NONFINITE_AXIS"),
        (float("inf"), "LAMBDA_NONFINITE_AXIS"),
        (1.5, "LAMBDA_AXIS_OUT_OF_RANGE"),
        (-0.1, "LAMBDA_AXIS_OUT_OF_RANGE"),
        (True, "LAMBDA_TYPE_INVALID"),
    ],
)
def test_a_zero_axis_does_not_mask_an_invalid_axis(bad, code):
    # v1 validates every axis before it computes, so the zero veto cannot hide a bad axis.
    # The vectors have no such row at d3443b0. This is the case an upstream vector should pin.
    for axes in ([0.0, bad], [bad, 0.0]):
        assert observe_lambda(axes, [0.5, 0.5]) == ("error", code), axes
        assert observe_gate(axes, [0.5, 0.5], 0.5) == ("BLOCK", code), axes


@pytest.mark.parametrize(
    "axes, weights, tau, code",
    [
        ([0.0, 10**400], [0.5, 0.5], 0.5, "LAMBDA_AXIS_OUT_OF_RANGE"),
        ([0.0, -(10**400)], [0.5, 0.5], 0.5, "LAMBDA_AXIS_OUT_OF_RANGE"),
        ([0.5], [10**400], 0.5, "LAMBDA_WEIGHT_SUM"),
        ([0.5], [-(10**400)], 0.5, "LAMBDA_WEIGHT_NONPOSITIVE"),
        ([0.5], [1.0], 10**400, "LAMBDA_TAU_INVALID"),
    ],
)
def test_large_finite_integers_are_rejected_by_domain(axes, weights, tau, code):
    assert observe_gate(axes, weights, tau) == ("BLOCK", code)


def test_lambda_gate_error_maps_to_block_and_nothing_else_does(monkeypatch):
    assert issubclass(LG.LambdaGateError, ValueError)
    assert observe_gate([], [], "f64:3fe999999999999a") == ("BLOCK", "LAMBDA_EMPTY")

    def boom(*_args, **_kwargs):
        raise RuntimeError("not a LambdaGateError")

    monkeypatch.setattr(LG, "evaluate", boom)
    with pytest.raises(RuntimeError):
        observe_gate([0.9], [1.0], 0.8)

    def plain_value_error(*_args, **_kwargs):
        raise ValueError("a plain ValueError is not a LambdaGateError")

    monkeypatch.setattr(LG, "evaluate", plain_value_error)
    with pytest.raises(ValueError, match="plain ValueError"):
        observe_gate([0.9], [1.0], 0.8)


def test_unclassified_error_message_fails_loudly():
    with pytest.raises(AssertionError, match="unclassified LambdaGateError message"):
        classify("a message the copy has never produced")
    # Every v1 code has a message, except the length check, which the copy lacks (AXIS_MISMATCH_KIND).
    assert {code for _, code in _MESSAGE_CODES} == (
        set(V1_ERROR_CODES) - {"LAMBDA_LENGTH_MISMATCH"}
    ) | {AXIS_MISMATCH}


def test_vectors_are_fed_as_index_to_axis_name_mappings(monkeypatch):
    assert as_axis_mapping(["f64:3fe0000000000000", 1, True, None, "0.9"]) == {
        "axis_0": 0.5,
        "axis_1": 1,
        "axis_2": True,
        "axis_3": None,
        "axis_4": "0.9",
    }
    assert as_axis_mapping(None) is None
    assert as_axis_mapping([]) == {}

    seen = []
    real = LG.lambda_score

    def spy(scores, weights):
        seen.append((scores, weights))
        return real(scores, weights)

    monkeypatch.setattr(LG, "lambda_score", spy)
    nominal = BY_ID["nominal"]
    observe_lambda(nominal["axes"], nominal["weights"])
    observe_gate(nominal["axes"], nominal["weights"], nominal["tau"])
    assert len(seen) == 2
    for scores, weights in seen:
        assert isinstance(scores, Mapping) and isinstance(weights, Mapping)
        assert list(scores) == list(weights) == [axis_name(i) for i in range(len(nominal["axes"]))]
        assert [scores[axis_name(i)] for i in range(4)] == [_decode(x) for x in nominal["axes"]]


def test_lambda_gate_is_loaded_by_file_path():
    assert LG.__name__ == _MODULE_NAME
    assert Path(LG.__file__).resolve() == LAMBDA_GATE_PATH.resolve()
    assert Path(LG.__spec__.origin).resolve() == LAMBDA_GATE_PATH.resolve()


def test_by_path_load_imports_neither_the_package_nor_in_toto(tmp_path):
    probe = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('_probe', {str(LAMBDA_GATE_PATH)!r})\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "sys.modules['_probe'] = module\n"
        "spec.loader.exec_module(module)\n"
        "assert module.lambda_score({'a': 0.25}, {'a': 1.0}) == 0.25\n"
        "hits = sorted(n for n in sys.modules\n"
        "              if n.split('.')[0] in ('szl_receipt', 'in_toto_attestation', 'cryptography'))\n"
        "print(','.join(hits))\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", probe], cwd=tmp_path, capture_output=True, text=True, timeout=60
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == ""


# ---------------------------------------------------------------- the fixture --


def test_source_records_the_ff01_merge_sha_and_the_canonical_digest():
    source = _read_source()
    assert source["source"] == f"szl-lambda-gate@{FF01_MERGE_SHA}"
    assert source["repo"] == "https://github.com/szl-holdings/szl-lambda-gate"
    assert source["commit"] == FF01_MERGE_SHA
    assert source["path"] == "spec/lambda_v1_vectors.json"
    assert source["canonical_sha256"] == VECTORS_CANONICAL_SHA256
    assert int(source["count"]) == VECTORS_COUNT


def test_vectors_canonical_digest_matches_source():
    assert _canonical_sha256(_load_vectors()) == _read_source()["canonical_sha256"]


def test_vectors_digest_survives_a_crlf_checkout():
    raw = VECTORS_PATH.read_bytes().replace(b"\r\n", b"\n")
    crlf = raw.replace(b"\n", b"\r\n")
    assert _canonical_sha256(json.loads(crlf.decode("utf-8"))) == VECTORS_CANONICAL_SHA256


def test_vectors_fixture_is_a_byte_copy_of_the_ff01_blob():
    # The git blob id over LF bytes. It is independent of core.autocrlf on checkout.
    data = VECTORS_PATH.read_bytes().replace(b"\r\n", b"\n")
    blob = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert blob == _read_source()["git_blob_sha1"]


def test_vectors_are_well_formed():
    doc = _load_vectors()
    assert doc["schema"] == "szl.lambda/v1.vectors"
    assert len(VECTORS) == VECTORS_COUNT
    assert len(set(VECTOR_IDS)) == len(VECTOR_IDS)
    for vector in VECTORS:
        tol = vector["value_tol"]
        assert isinstance(tol, float) and 0.0 < tol < 1e-6, vector["id"]
        expect = vector["expect"]
        assert ("error" in expect) != ("value_f64" in expect), vector["id"]
        assert expect.get("error") in (None,) + V1_ERROR_CODES, vector["id"]
        assert expect["verdict"] in V1_VERDICTS, vector["id"]
        if "value_f64" in expect:
            assert 0.0 <= _decode(expect["value_f64"]) <= 1.0, vector["id"]
