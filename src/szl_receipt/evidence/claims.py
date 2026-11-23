# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""Typed evidence claims for model cards — assertion can never render as
verification.

Doctrine (non-negotiable):
  - Every claim carries exactly one status from the closed enum
    MEASURED | REPRODUCED | SELF_ASSERTED | MISSING.
  - Only MEASURED and REPRODUCED count as *verified* evidence. A
    SELF_ASSERTED claim is never upgraded by wording, prose, or omitting
    the status.
  - MEASURED / REPRODUCED claims MUST carry an evidence URI, a sha256
    artifact digest, an ISO-8601 UTC evaluation timestamp, and an
    evaluator identity. Absent or malformed evidence is a load-time
    failure (fail-closed), not a silent downgrade.
  - MISSING claims MUST carry a ``named_gap`` describing what is absent.
    Missing evidence may be rendered as MISSING — never as zero, passed,
    or "not applicable".
"""
from __future__ import annotations

import re
import string
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

MEASURED = "MEASURED"
REPRODUCED = "REPRODUCED"
SELF_ASSERTED = "SELF_ASSERTED"
MISSING = "MISSING"

ALL_STATUSES = (MEASURED, REPRODUCED, SELF_ASSERTED, MISSING)
VERIFIED_STATUSES = (MEASURED, REPRODUCED)

#: Required claim slots on a fully evidenced model. Coverage denominators
#: are computed over exactly these slots — nothing else inflates coverage.
REQUIRED_CLAIM_SLOTS = (
    "identity",
    "dataset",
    "evaluation",
    "environment",
    "safety",
    "publication",
)

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
# RFC3339, UTC only. Naive timestamps and non-zero offsets are rejected:
# evidence without an unambiguous timezone is not evidence.
_TIMESTAMP_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|\+00:00)$"
)
_CLAIM_ID_ALPHABET = set(string.ascii_lowercase + string.digits + "-_/")


class ClaimValidationError(ValueError):
    """Raised when a claim dict violates the evidence contract."""


def _require(condition: bool, key: str, problem: str) -> None:
    if not condition:
        raise ClaimValidationError(f"claim field {key!r}: {problem}")


def is_valid_digest(value: Any) -> bool:
    """True iff *value* is a lowercase 64-char hex sha256 string."""
    return isinstance(value, str) and bool(_DIGEST_RE.match(value))


def is_valid_utc_timestamp(value: Any) -> bool:
    """True iff *value* is an RFC3339 Z / +00:00 UTC timestamp."""
    return isinstance(value, str) and bool(_TIMESTAMP_RE.match(value))


@dataclass(frozen=True)
class Claim:
    """One typed claim on a model, with its evidence or its named gap."""

    claim_id: str
    slot: str
    status: str
    summary: str = ""
    evidence_uri: str = ""
    artifact_digest: str = ""
    evaluated_at: str = ""
    evaluator: str = ""
    named_gap: str = ""
    max_age_days: Optional[int] = None
    notes: str = ""

    def __post_init__(self) -> None:
        validate_claim(self)

    @property
    def verified(self) -> bool:
        """True for MEASURED / REPRODUCED only — never for prose."""
        return self.status in VERIFIED_STATUSES

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "claim_id": self.claim_id,
            "slot": self.slot,
            "status": self.status,
        }
        if self.summary:
            out["summary"] = self.summary
        if self.status in VERIFIED_STATUSES:
            out.update(
                {
                    "evidence_uri": self.evidence_uri,
                    "artifact_digest": self.artifact_digest,
                    "evaluated_at": self.evaluated_at,
                    "evaluator": self.evaluator,
                }
            )
            if self.max_age_days is not None:
                out["max_age_days"] = self.max_age_days
        elif self.status == MISSING:
            out["named_gap"] = self.named_gap
        if self.notes:
            out["notes"] = self.notes
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Claim":
        if not isinstance(data, Mapping):
            raise ClaimValidationError(
                "claim must be a JSON object, got "
                f"{type(data).__name__}"
            )
        missing = [k for k in ("claim_id", "slot", "status") if k not in data]
        if missing:
            raise ClaimValidationError(f"claim missing required keys: {missing}")
        return cls(
            claim_id=data["claim_id"],
            slot=data["slot"],
            status=data["status"],
            summary=str(data.get("summary", "")),
            evidence_uri=data.get("evidence_uri", ""),
            artifact_digest=data.get("artifact_digest", ""),
            evaluated_at=data.get("evaluated_at", ""),
            evaluator=data.get("evaluator", ""),
            named_gap=data.get("named_gap", ""),
            max_age_days=data.get("max_age_days"),
            notes=str(data.get("notes", "")),
        )


def validate_claim(claim: Claim) -> None:
    """Fail-closed validation of one claim. Raises ClaimValidationError."""
    _require(
        isinstance(claim.claim_id, str)
        and 0 < len(claim.claim_id) <= 128
        and all(c in _CLAIM_ID_ALPHABET for c in claim.claim_id),
        "claim_id",
        "lowercase slug of <=128 chars from [a-z0-9-_/] required",
    )
    _require(
        claim.slot in REQUIRED_CLAIM_SLOTS,
        "slot",
        f"must be one of {list(REQUIRED_CLAIM_SLOTS)}",
    )
    _require(
        claim.status in ALL_STATUSES,
        "status",
        f"must be one of the closed enum {list(ALL_STATUSES)}",
    )
    if claim.status in VERIFIED_STATUSES:
        _require(
            isinstance(claim.evidence_uri, str)
            and len(claim.evidence_uri) > 0
            and len(claim.evidence_uri) <= 2048,
            "evidence_uri",
            "a resolvable evidence URI is required for "
            f"{claim.status} claims",
        )
        _require(
            is_valid_digest(claim.artifact_digest),
            "artifact_digest",
            "a lowercase 64-char hex sha256 digest of the evidence "
            "artifact is required; hand-waving is not Measurement",
        )
        _require(
            is_valid_utc_timestamp(claim.evaluated_at),
            "evaluated_at",
            "an RFC3339 UTC (Z) evaluation timestamp is required",
        )
        _require(
            isinstance(claim.evaluator, str) and len(claim.evaluator) > 0,
            "evaluator",
            "the evaluating identity (person, service, or workflow) "
            f"is required for {claim.status} claims",
        )
        if claim.max_age_days is not None:
            _require(
                isinstance(claim.max_age_days, int)
                and not isinstance(claim.max_age_days, bool)
                and claim.max_age_days > 0,
                "max_age_days",
                "optional freshness horizon must be a positive integer "
                "of days",
            )
    elif claim.status == MISSING:
        _require(
            isinstance(claim.named_gap, str) and len(claim.named_gap) > 0,
            "named_gap",
            "a MISSING claim must name its gap; silence is not coverage",
        )
