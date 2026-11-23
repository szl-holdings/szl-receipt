# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""Inventory and coverage ledger: denominators explicit, gaps named."""
import json
import pathlib

import pytest

from szl_receipt.evidence.claims import MEASURED, MISSING, SELF_ASSERTED
from szl_receipt.evidence.inventory import (
    FULLY_EVIDENCED,
    INVENTORY_ONLY,
    PARTIALLY_EVIDENCED,
    EvidenceInventory,
    InventoryLoadError,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "evidence"


def _load_fixtures():
    return EvidenceInventory.load_directory(FIXTURES)


def test_fixture_directory_loads():
    inv = _load_fixtures()
    assert len(inv) == 3


def test_golden_model_is_fully_evidenced():
    inv = _load_fixtures()
    rec = inv.get("szl-canary-measured")
    assert rec is not None
    assert rec.classification == FULLY_EVIDENCED


def test_partial_model_classification_and_gaps():
    inv = _load_fixtures()
    rec = inv.get("szl-canary-partial")
    assert rec.classification == PARTIALLY_EVIDENCED
    gaps = rec.slot_gaps()
    assert "evaluation" in gaps
    assert "no held-out evaluation" in gaps["evaluation"].lower()


def test_inventory_only_model_every_slot_named():
    inv = _load_fixtures()
    rec = inv.get("szl-canary-inventory-only")
    assert rec.classification == INVENTORY_ONLY
    gaps = rec.slot_gaps()
    assert len(gaps) == 6
    assert all("no claims recorded" in g for g in gaps.values())


def test_coverage_denominator_is_explicit():
    inv = _load_fixtures()
    cov = inv.coverage()
    assert cov["denominator"] == 3
    counts = cov["classification_counts"]
    assert counts[FULLY_EVIDENCED] == 1
    assert counts[PARTIALLY_EVIDENCED] == 1
    assert counts[INVENTORY_ONLY] == 1
    assert sum(counts.values()) == cov["denominator"]


def test_slot_coverage_counts_match_denominator():
    inv = _load_fixtures()
    cov = inv.coverage()
    for slot, totals in cov["slot_coverage"].items():
        assert sum(totals.values()) == cov["denominator"], slot


def test_negative_evidence_lists_every_gap():
    inv = _load_fixtures()
    cov = inv.coverage()
    negative = cov["negative_evidence"]
    # golden model contributes nothing; partial contributes 5; the
    # inventory-only model contributes 6 (all slots).
    assert len(negative) == 11
    for entry in negative:
        assert entry["model_id"]
        assert entry["slot"]
        assert entry["named_gap"]
        assert entry["issue"] in (MISSING, SELF_ASSERTED, "stale")


def test_missing_never_reported_as_pass():
    inv = _load_fixtures()
    for rec in inv.records:
        payload = json.dumps(rec.to_dict())
        assert '"pass"' not in payload.lower()


def test_compare_names_unknown_ids():
    inv = _load_fixtures()
    result = inv.compare(
        ["szl-canary-measured", "does-not-exist", "szl-canary-partial"]
    )
    assert result["unknown"] == ["does-not-exist"]
    assert [m["model_id"] for m in result["models"]] == [
        "szl-canary-measured",
        "szl-canary-partial",
    ]


def test_duplicate_claim_id_is_contradiction(tmp_path):
    record = {
        "model_id": "m",
        "revision": "r1",
        "claims": [
            {
                "claim_id": "evaluation/heldout",
                "slot": "evaluation",
                "status": MEASURED,
                "evidence_uri": "https://example.invalid/a",
                "artifact_digest": "a" * 64,
                "evaluated_at": "2026-11-22T00:00:00Z",
                "evaluator": "ci",
            },
            {
                "claim_id": "evaluation/heldout",
                "slot": "evaluation",
                "status": MISSING,
                "named_gap": "contradictory duplicate",
            },
        ],
    }
    fp = tmp_path / "m.json"
    fp.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(InventoryLoadError) as excinfo:
        EvidenceInventory.load_directory(tmp_path)
    assert "contradictory" in str(excinfo.value)
    assert fp.name in str(excinfo.value)


def test_invalid_json_fail_closed(tmp_path):
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(InventoryLoadError) as excinfo:
        EvidenceInventory.load_directory(tmp_path)
    assert "bad.json" in str(excinfo.value)


def test_self_asserted_message_never_says_measured():
    inv = _load_fixtures()
    rec = inv.get("szl-canary-partial")
    msg = rec.slot_gaps()["dataset"]
    assert "self-asserted" in msg
    assert MEASURED not in msg


def test_duplicate_model_id_rejected(tmp_path):
    record = {"model_id": "dup", "revision": "r", "claims": []}
    (tmp_path / "a.json").write_text(json.dumps(record), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(InventoryLoadError):
        EvidenceInventory.load_directory(tmp_path)
