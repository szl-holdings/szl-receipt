# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""Model evidence inventory and coverage ledger.

Doctrine (non-negotiable):
  - The coverage denominator is explicit: every stat reports both the
    count and the total it was computed over. "418 generated cards" is
    never equal to "418 verified models".
  - A model is classified ``fully_evidenced`` only when every required
    slot has at least one verified claim (MEASURED or REPRODUCED);
    missing slots are reported as MISSING with named gaps — never
    silently dropped and never rendered as passed.
  - Loading is fail-closed: an evidence file that violates the claim
    contract aborts the load with the offending file named. There is no
    partial-load mode and no best-effort parsing.
  - Release admission and model evaluation stay separated: the
    ``publication`` slot is recorded like any other evidence, not used
    as an umbrella verdict.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .claims import (
    MEASURED,
    MISSING,
    REPRODUCED,
    SELF_ASSERTED,
    REQUIRED_CLAIM_SLOTS,
    VERIFIED_STATUSES,
    Claim,
    ClaimValidationError,
)

FULLY_EVIDENCED = "fully_evidenced"
PARTIALLY_EVIDENCED = "partially_evidenced"
INVENTORY_ONLY = "inventory_only"

CLASSIFICATIONS = (FULLY_EVIDENCED, PARTIALLY_EVIDENCED, INVENTORY_ONLY)

_SLOT_STATUS_PRIORITY = (MEASURED, REPRODUCED, SELF_ASSERTED, MISSING)


class InventoryLoadError(ValueError):
    """Raised when an evidence file or directory fails validation."""


@dataclass(frozen=True)
class ModelEvidence:
    """All typed claims recorded for one model at one revision."""

    model_id: str
    revision: str
    claims: tuple = ()
    source_file: str = ""

    @classmethod
    def from_dict(
        cls, data: Dict[str, Any], source_file: str = ""
    ) -> "ModelEvidence":
        if not isinstance(data, dict):
            raise InventoryLoadError(f"{source_file}: record must be an object")
        for key in ("model_id", "revision"):
            value = data.get(key)
            if not isinstance(value, str) or not value.strip():
                raise InventoryLoadError(
                    f"{source_file}: field {key!r} must be a non-empty string"
                )
        raw_claims = data.get("claims", [])
        if not isinstance(raw_claims, list):
            raise InventoryLoadError(
                f"{source_file}: field 'claims' must be an array"
            )
        claims: List[Claim] = []
        seen_ids = {}
        for i, raw in enumerate(raw_claims):
            try:
                claim = Claim.from_dict(raw)
            except ClaimValidationError as exc:
                raise InventoryLoadError(
                    f"{source_file}: claims[{i}] invalid: {exc}"
                ) from exc
            if claim.claim_id in seen_ids:
                raise InventoryLoadError(
                    f"{source_file}: contradictory claims — claim_id "
                    f"{claim.claim_id!r} declared at positions "
                    f"{seen_ids[claim.claim_id]} and {i}"
                )
            seen_ids[claim.claim_id] = i
            claims.append(claim)
        return cls(
            model_id=data["model_id"],
            revision=data["revision"],
            claims=tuple(claims),
            source_file=source_file,
        )

    # -- derived views ------------------------------------------------

    def slot_claims(self, slot: str) -> List[Claim]:
        return [c for c in self.claims if c.slot == slot]

    def slot_status(self, slot: str) -> str:
        """Status of one slot: best evidence present, else MISSING."""
        statuses = {c.status for c in self.slot_claims(slot)}
        for candidate in _SLOT_STATUS_PRIORITY:
            if candidate in statuses:
                return candidate
        return MISSING

    def slot_gaps(self) -> Dict[str, str]:
        """Named gap for every unverified slot. Never empty prose."""
        gaps: Dict[str, str] = {}
        for slot in REQUIRED_CLAIM_SLOTS:
            claims = self.slot_claims(slot)
            if not claims:
                gaps[slot] = f"no claims recorded for slot {slot}"
                continue
            for c in claims:
                if c.status == MISSING:
                    gaps[slot] = c.named_gap
                    break
                if c.status == SELF_ASSERTED:
                    gaps[slot] = (
                        f"only self-asserted (claim {c.claim_id}); no "
                        "measured or reproduced artifact linked"
                    )
            else:
                continue
            continue
        return gaps

    @property
    def classification(self) -> str:
        verified_slots = sum(
            1 for s in REQUIRED_CLAIM_SLOTS if self.slot_status(s) in VERIFIED_STATUSES
        )
        if verified_slots == len(REQUIRED_CLAIM_SLOTS):
            return FULLY_EVIDENCED
        if verified_slots == 0:
            return INVENTORY_ONLY
        return PARTIALLY_EVIDENCED

    def stale_claims(self, as_of: Optional[datetime] = None) -> List[str]:
        """claim_ids whose freshness horizon has passed at *as_of*.

        Staleness is surfacing, not upgrading: a stale claim keeps its
        status but appears in the negative-evidence ledger.
        """
        if as_of is None:
            return []
        stale: List[str] = []
        for c in self.claims:
            if c.status in VERIFIED_STATUSES and c.max_age_days is not None:
                evaluated = _parse_utc(c.evaluated_at)
                horizon = timedelta(days=c.max_age_days)
                if evaluated + horizon <= as_of:
                    stale.append(c.claim_id)
        return stale

    def to_dict(self) -> Dict[str, Any]:
        slots: Dict[str, Any] = {}
        for slot in REQUIRED_CLAIM_SLOTS:
            entry: Dict[str, Any] = {
                "status": self.slot_status(slot),
                "claims": [c.to_dict() for c in self.slot_claims(slot)],
            }
            if slot in self.slot_gaps():
                entry["named_gap"] = self.slot_gaps()[slot]
            slots[slot] = entry
        return {
            "model_id": self.model_id,
            "revision": self.revision,
            "classification": self.classification,
            "slots": slots,
        }


def _parse_utc(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


class EvidenceInventory:
    """A validated, immutable inventory of model evidence records."""

    def __init__(self, records: List[ModelEvidence]):
        by_id: Dict[str, ModelEvidence] = {}
        for rec in records:
            if rec.model_id in by_id:
                raise InventoryLoadError(
                    f"duplicate model_id {rec.model_id!r} in "
                    f"{rec.source_file!r} and {by_id[rec.model_id].source_file!r}"
                )
            by_id[rec.model_id] = rec
        self._records: List[ModelEvidence] = records
        self._by_id = by_id

    @classmethod
    def load_directory(cls, path: str | Path) -> "EvidenceInventory":
        """Load every ``*.json`` in *path*. Fail-closed on any violation."""
        root = Path(path)
        if not root.is_dir():
            raise InventoryLoadError(f"evidence directory not found: {root}")
        files = sorted(p for p in root.glob("*.json"))
        if not files:
            raise InventoryLoadError(f"no evidence records under {root}")
        records: List[ModelEvidence] = []
        for fp in files:
            try:
                text = fp.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise InventoryLoadError(f"{fp}: unreadable ({exc})") from exc
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise InventoryLoadError(f"{fp}: invalid JSON ({exc})") from exc
            records.append(ModelEvidence.from_dict(data, source_file=str(fp)))
        return cls(records)

    # -- lookups ------------------------------------------------------

    @property
    def records(self) -> List[ModelEvidence]:
        return list(self._records)

    def get(self, model_id: str) -> Optional[ModelEvidence]:
        return self._by_id.get(model_id)

    def __len__(self) -> int:
        return len(self._records)

    # -- ledger -------------------------------------------------------

    def coverage(self, as_of: Optional[datetime] = None) -> Dict[str, Any]:
        """Coverage ledger with an explicit denominator and gaps named."""
        n = len(self._records)
        counts = {c: 0 for c in CLASSIFICATIONS}
        slot_totals: Dict[str, Dict[str, int]] = {
            slot: {s: 0 for s in _SLOT_STATUS_PRIORITY} for slot in REQUIRED_CLAIM_SLOTS
        }
        negative: List[Dict[str, str]] = []
        for rec in self._records:
            counts[rec.classification] += 1
            for slot in REQUIRED_CLAIM_SLOTS:
                slot_totals[slot][rec.slot_status(slot)] += 1
            for slot, gap in rec.slot_gaps().items():
                negative.append(
                    {
                        "model_id": rec.model_id,
                        "slot": slot,
                        "issue": rec.slot_status(slot),
                        "named_gap": gap,
                    }
                )
            for claim_id in rec.stale_claims(as_of=as_of):
                negative.append(
                    {
                        "model_id": rec.model_id,
                        "slot": next(
                            c.slot for c in rec.claims if c.claim_id == claim_id
                        ),
                        "issue": "stale",
                        "named_gap": f"claim {claim_id} exceeded its "
                        "freshness horizon",
                    }
                )
        return {
            "denominator": n,
            "classification_counts": counts,
            "slot_coverage": slot_totals,
            "negative_evidence": negative,
        }

    def compare(self, model_ids: List[str]) -> Dict[str, Any]:
        """Side-by-side claim matrix; unknown ids are named, not guessed."""
        cols: List[Dict[str, Any]] = []
        unknown: List[str] = []
        for mid in model_ids:
            rec = self.get(mid)
            if rec is None:
                unknown.append(mid)
                continue
            cols.append(
                {
                    "model_id": rec.model_id,
                    "revision": rec.revision,
                    "classification": rec.classification,
                    "slots": {
                        s: rec.slot_status(s) for s in REQUIRED_CLAIM_SLOTS
                    },
                    "gaps": rec.slot_gaps(),
                }
            )
        return {"requested": list(model_ids), "unknown": unknown, "models": cols}
