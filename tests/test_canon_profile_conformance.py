"""Canonicalization conformance: this repo's serializer must reproduce the
'szl.lambda/v1' column of the shared SZL canonicalization vectors byte-for-byte.

The vectors (tests/fixtures/canonicalization-v1.json) are a copy of
governed-receipt-spec conformance/canonicalization-v1.json. This test only
pins today's bytes so a silent drift between estate copies fails CI; it does
not change any serializer or any existing digest.
"""
import hashlib
import json
from pathlib import Path

import pytest

from szl_receipt._canonical import canonical_json

PROFILE = 'szl.lambda/v1'
REJECTS = ValueError
VECTORS = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "canonicalization-v1.json").read_text("utf-8"))


def _decode(x):
    if isinstance(x, dict):
        if set(x) == {"$float"}:
            return float(x["$float"])
        return {k: _decode(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_decode(v) for v in x]
    return x


def _bytes(value):
    out = canonical_json(value)
    return out.encode("utf-8") if isinstance(out, str) else out


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["id"])
def test_matches_profile(case):
    expected = case["expected"][PROFILE]
    value = _decode(case["input"])
    if expected.get("reject"):
        with pytest.raises(REJECTS):
            _bytes(value)
        return
    if PROFILE in case.get("implementations_may_reject", []):
        try:
            got = _bytes(value)
        except REJECTS:
            return
    else:
        got = _bytes(value)
    assert got.decode("utf-8") == expected["utf8"]
    assert hashlib.sha256(got).hexdigest() == expected["sha256"]
