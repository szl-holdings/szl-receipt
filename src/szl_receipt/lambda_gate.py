# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""
Λ (Lambda-Spine) aggregator — the SZL governance roll-up, as a dependency-light
reference kernel usable inside a Proof-Carrying Inference (PCI) receipt.

Λ is the **weighted geometric mean** of per-axis scores::

    Λ(x) = Π_i x_i ** w_i        with   x_i ∈ [0, 1],  w_i > 0,  Σ_i w_i = 1.

It is deliberately **non-compensatory**: a single zeroed axis drives the whole
aggregate to 0 — a weakness that cannot be bought back by strength elsewhere. It
is an **advisory** gate (Λ ≥ θ), NOT a claim of proven trust or correctness.

Honesty doctrine (never weakened):
  * Λ is advisory. A pass means "cleared an advisory non-compensatory gate",
    never "provably safe/correct".
  * Uniqueness of Λ under the SZL axioms is CONDITIONAL (Theorem U,
    machine-checked). The UNCONDITIONAL uniqueness statement is machine-checked
    **false as stated** (Conjecture 1) — this module never asserts otherwise.

Companion kernel: github.com/szl-holdings/szl-lambda-gate
Concept DOI: 10.5281/zenodo.19944926
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Mapping

#: Tolerance for the Σ wᵢ = 1 constraint.
WEIGHT_SUM_TOL = 1e-9

KERNEL = "szl-lambda-gate"
FORM = "weighted-geometric-mean"

ADVISORY_NOTE = (
    "Advisory, non-compensatory governance roll-up. A pass clears a threshold; "
    "it is NOT a proof of correctness, safety, or conformity. Λ-uniqueness is "
    "conditional (Theorem U); unconditional uniqueness is machine-checked false "
    "as stated (Conjecture 1)."
)


class LambdaGateError(ValueError):
    """Raised on an ill-formed Λ input (out-of-range score, bad weights)."""


def _as_real(value: object, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LambdaGateError(f"{what} is not a real number: {value!r}")
    return float(value)


def lambda_score(
    scores: Mapping[str, float], weights: Mapping[str, float]
) -> float:
    """Compute Λ(x) = Π xᵢ ** wᵢ over the shared axes.

    Validates xᵢ ∈ [0, 1], wᵢ > 0, matching axis keys, and Σ wᵢ = 1 (within
    :data:`WEIGHT_SUM_TOL`). Non-compensatory: any xᵢ == 0 yields Λ == 0.

    Raises:
        LambdaGateError: on any ill-formed input. Λ is never guessed.
    """
    if not scores or not weights:
        raise LambdaGateError("scores and weights must both be non-empty")
    if set(scores) != set(weights):
        raise LambdaGateError(
            f"axis mismatch: scores={sorted(scores)} weights={sorted(weights)}"
        )

    wsum = 0.0
    for axis, w in weights.items():
        wv = _as_real(w, f"weight for {axis!r}")
        if wv <= 0.0:
            raise LambdaGateError(f"weight for {axis!r} must be > 0 (got {wv})")
        wsum += wv
    if abs(wsum - 1.0) > WEIGHT_SUM_TOL:
        raise LambdaGateError(f"weights must sum to 1 (got {wsum})")

    acc = 0.0
    for axis, x in scores.items():
        xv = _as_real(x, f"score for {axis!r}")
        if xv < 0.0 or xv > 1.0:
            raise LambdaGateError(f"score for {axis!r} must be in [0,1] (got {xv})")
        if xv == 0.0:
            return 0.0  # non-compensatory collapse — no other axis can buy it back
        acc += float(weights[axis]) * math.log(xv)
    return math.exp(acc)


@dataclass(frozen=True)
class LambdaVerdict:
    """A bound, self-describing Λ evaluation (the advisory verdict record)."""

    lam: float
    theta: float
    verdict: str  # "advisory-pass" | "advisory-fail"
    scores: Dict[str, float]
    weights: Dict[str, float]
    kernel: str = KERNEL
    form: str = FORM
    note: str = ADVISORY_NOTE

    def to_dict(self) -> Dict[str, object]:
        """Canonical, JSON-friendly dict for binding inside a receipt body."""
        return {
            "kernel": self.kernel,
            "form": self.form,
            "scores": dict(self.scores),
            "weights": dict(self.weights),
            "theta": self.theta,
            "lambda": self.lam,
            "verdict": self.verdict,
            "note": self.note,
        }


def evaluate(
    scores: Mapping[str, float], weights: Mapping[str, float], theta: float
) -> LambdaVerdict:
    """Evaluate Λ and render the advisory Λ ≥ θ verdict.

    Args:
        scores: axis -> score in [0, 1].
        weights: axis -> weight > 0, summing to 1.
        theta: advisory threshold in [0, 1].

    Returns:
        A :class:`LambdaVerdict` carrying Λ, θ, the inputs, and the advisory
        verdict ("advisory-pass" iff Λ ≥ θ, else "advisory-fail").
    """
    tv = _as_real(theta, "theta")
    if tv < 0.0 or tv > 1.0:
        raise LambdaGateError(f"theta must be in [0,1] (got {tv})")
    lam = lambda_score(scores, weights)
    verdict = "advisory-pass" if lam >= tv else "advisory-fail"
    return LambdaVerdict(
        lam=lam,
        theta=tv,
        verdict=verdict,
        scores={k: float(v) for k, v in scores.items()},
        weights={k: float(v) for k, v in weights.items()},
    )
