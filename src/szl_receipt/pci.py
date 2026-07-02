# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""
Proof-Carrying Inference (PCI) — the offline-verifiable evolution of PCGI.

The PCGI spine (:mod:`szl_receipt.sdk`) already binds
model + input + output + policy + energy (+ BFT witnesses) into ONE signed,
tamper-evident receipt. PCI adds the two bindings that turn a governed-inference
receipt into an **offline-verifiable governance warrant**:

  * a **Λ-verdict** (:mod:`szl_receipt.lambda_gate`) — the exact
    non-compensatory weighted-geometric-mean roll-up Λ = Π xᵢ**wᵢ and its
    advisory threshold Λ ≥ θ. The verifier **recomputes Λ** from the bound
    scores, so a wrong Λ is caught offline (not merely asserted); and
  * a **machine-checked spec reference** (``σ``) — which locked ``lutar-lean``
    invariants the receipt substrate is modelled by, protected by a **tier
    guard** that REFUSES to certify overclaims: unconditional Λ-uniqueness
    (Conjecture 1, machine-checked false as stated) and unconditional Khipu BFT
    safety (Conjecture 2, open).

Both bindings ride inside the sanctioned PCGI ``extra`` extension point, so they
are part of the signed body digest (tamper-evident) WITHOUT forking the
battle-tested spine. A PCI receipt is first verified by the existing
:func:`szl_receipt.sdk.verify_emitted_receipt`; PCI then re-checks Λ, the spec
tier guard, and energy honesty. Keyless emission stays UNSIGNED-honest — the
verifier never returns a fake pass.

Anchoring prior art (cited, not claimed as ours):
  * G. Necula, "Proof-Carrying Code", POPL 1997, doi:10.1145/263699.263712.
  * Kol, Ben-Shahar, Sulimany, Englund, "A machine-verified proof of a
    quantum-optimization conjecture", arXiv:2606.29687 (2026) — LLM proposes /
    Lean 4 certifies, the same loop SZL points at governance.
SZL corpus concept DOI: 10.5281/zenodo.19944926.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from . import lambda_gate
from .attest import UNAVAILABLE
from .lambda_gate import LambdaVerdict
from .sdk import emit_receipt
from .sdk import verify_receipt as _verify_pcgi

#: Profile tag stamped into ``body["extra"]["pci_profile"]``.
PCI_PROFILE = "https://a-11-oy.com/pci/receipt/v1"

#: Tolerance for the offline Λ recomputation check.
LAMBDA_RECOMPUTE_TOL = 1e-9

#: Default machine-checked reference (lutar-lean locked tier).
DEFAULT_SPEC_REF = "github.com/szl-holdings/lutar-lean"
LOCKED_INVARIANTS: Tuple[str, ...] = ("F1", "F4", "F7", "F18", "F22", "TheoremU")

#: Overclaims the tier guard REFUSES to certify (machine-checked non-theorems).
#: Maps a forbidden claim token -> the verification reason returned on refusal.
FORBIDDEN_CLAIMS: Dict[str, str] = {
    "lambda-uniqueness-unconditional": "overclaim-conjecture1",
    "khipu-bft-safety-unconditional": "overclaim-conjecture2",
}


@dataclass(frozen=True)
class SpecRef:
    """A reference to the machine-checked spec (``σ``) the receipt is modelled by.

    ``claims`` lets a producer state what it relies on; the verifier's tier guard
    rejects any claim in :data:`FORBIDDEN_CLAIMS`, so an honest producer can
    never accidentally certify a machine-checked non-theorem.
    """

    ref: str = DEFAULT_SPEC_REF
    locked_count: int = 8
    invariants: Sequence[str] = LOCKED_INVARIANTS
    tier: str = "locked"
    claims: Sequence[str] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ref": self.ref,
            "locked_count": self.locked_count,
            "invariants": list(self.invariants),
            "tier": self.tier,
            "claims": list(self.claims),
        }


@dataclass(frozen=True)
class PCIResult:
    """Structured outcome of :func:`verify_pci_receipt`.

    ``ok`` means the receipt is well-formed, correctly signed (or the caller
    accepted UNSIGNED-honest), non-overclaiming, and its Λ recomputes. The
    ADVISORY verdict (pass/fail of Λ ≥ θ) is carried separately in ``advisory``
    — an advisory-fail is still a *valid* receipt, just a negative verdict.
    """

    ok: bool
    reason: str
    advisory: Optional[str] = None  # "advisory-pass" | "advisory-fail" | None
    lambda_value: Optional[float] = None
    energy: str = UNAVAILABLE
    signed: bool = False

    def as_tuple(self) -> Tuple[bool, str]:
        return (self.ok, self.reason)


def emit_pci_receipt(
    *,
    model_id: str,
    input_digest: str,
    output_digest: str,
    policy_id: str,
    lambda_verdict: LambdaVerdict,
    spec: Optional[SpecRef] = None,
    attestation: Optional[Mapping[str, Any]] = None,
    energy_joules: Optional[float] = None,
    witnesses: Optional[Sequence[Any]] = None,
    organ: str = "unknown",
    private_key_pem: Optional[str | bytes] = None,
    keyid: str = "",
    extra: Optional[Mapping[str, Any]] = None,
    **emit_kwargs: Any,
) -> Dict[str, Any]:
    """Emit ONE signed PCI receipt: a PCGI receipt + Λ-verdict + spec (``σ``).

    Args:
        model_id/input_digest/output_digest/policy_id: the governed decision,
            forwarded verbatim to :func:`szl_receipt.sdk.emit_receipt`.
        lambda_verdict: a :class:`szl_receipt.lambda_gate.LambdaVerdict` from
            :func:`szl_receipt.lambda_gate.evaluate` — bound and re-checked.
        spec: the machine-checked spec reference (``σ``). Defaults to the
            lutar-lean locked tier with no extra claims.
        attestation: optional confidential-execution (``τ``) evidence, stored
            verbatim. When omitted, an honest ``{"status": "UNAVAILABLE"}``
            placeholder is recorded — never a fabricated quote.
        energy_joules: measured joules (verbatim) or ``None`` for honest
            ``UNAVAILABLE``. Never fabricated.
        witnesses/organ/private_key_pem/keyid/extra: forwarded to the spine.

    Returns:
        The composite PCGI dict (schema/digest/body/envelope/statement/
        compliance) with the PCI bindings under ``body["extra"]``.
    """
    if not isinstance(lambda_verdict, LambdaVerdict):
        raise TypeError(
            "lambda_verdict must be a lambda_gate.LambdaVerdict "
            "(use lambda_gate.evaluate(scores, weights, theta))"
        )
    spec = spec or SpecRef()

    pci_extra: Dict[str, Any] = {
        "pci_profile": PCI_PROFILE,
        "lambda_verdict": lambda_verdict.to_dict(),
        "spec": spec.to_dict(),
        "attestation": dict(attestation)
        if attestation is not None
        else {"status": "UNAVAILABLE", "kind": "confidential-exec"},
    }
    if extra:
        pci_extra["caller"] = dict(extra)

    return emit_receipt(
        model_id=model_id,
        input_digest=input_digest,
        output_digest=output_digest,
        policy_id=policy_id,
        energy_joules=energy_joules,
        witnesses=witnesses,
        organ=organ,
        private_key_pem=private_key_pem,
        keyid=keyid,
        extra=pci_extra,
        **emit_kwargs,
    )


def verify_pci_receipt(
    composite: Optional[Mapping[str, Any]],
    public_key_pem: Optional[str | bytes] = None,
    *,
    require_signed: bool = False,
    require_measured_energy: bool = False,
) -> PCIResult:
    """Offline-verify a PCI receipt. Never returns a fake pass.

    Order of checks (fail-closed at the first violation):
      1. spine integrity + signature via
         :func:`szl_receipt.sdk.verify_emitted_receipt` (or UNSIGNED-honest);
      2. it actually carries the PCI profile;
      3. energy honesty (optionally require MEASURED);
      4. spec tier guard — refuse :data:`FORBIDDEN_CLAIMS` overclaims;
      5. Λ recomputation from the bound scores/weights + verdict consistency.

    Returns:
        A :class:`PCIResult`. ``ok`` is True only when every integrity/honesty
        check holds; the advisory Λ ≥ θ verdict is reported in ``advisory``.
    """
    ok, why = _verify_pcgi(composite, public_key_pem=public_key_pem)
    body = (composite or {}).get("body") or {} if isinstance(composite, Mapping) else {}
    env = (composite or {}).get("envelope") or {} if isinstance(composite, Mapping) else {}
    signed = bool(env.get("signed"))
    if not ok:
        return PCIResult(ok=False, reason=why, signed=signed)
    if require_signed and not signed:
        return PCIResult(ok=False, reason="unsigned-honest", signed=signed)

    extra = body.get("extra") or {}
    if extra.get("pci_profile") != PCI_PROFILE:
        return PCIResult(ok=False, reason="not-a-pci-receipt", signed=signed)

    # (3) energy honesty. The spine renders measured energy VERBATIM as
    # ``{"joules": <real>, "unit": "J"}`` and unmeasured as the string
    # ``"UNAVAILABLE"`` — a joule is never fabricated. Treat a dict carrying a
    # real (non-bool) ``joules`` as MEASURED; everything else as UNAVAILABLE.
    energy = body.get("energy", UNAVAILABLE)
    joules = energy.get("joules") if isinstance(energy, Mapping) else None
    is_measured = isinstance(joules, (int, float)) and not isinstance(joules, bool)
    energy_label = "MEASURED" if is_measured else (
        energy if isinstance(energy, str) else UNAVAILABLE
    )
    if require_measured_energy and not is_measured:
        return PCIResult(
            ok=False, reason="energy-unavailable", energy=energy_label, signed=signed
        )

    # (4) spec tier guard — refuse machine-checked non-theorems
    spec = extra.get("spec") or {}
    for claim in spec.get("claims", []) or []:
        code = FORBIDDEN_CLAIMS.get(str(claim))
        if code:
            return PCIResult(
                ok=False, reason=code, energy=energy_label, signed=signed
            )

    # (5) Λ recomputation from the BOUND scores/weights
    lv = extra.get("lambda_verdict") or {}
    try:
        recomputed = lambda_gate.lambda_score(
            lv.get("scores", {}), lv.get("weights", {})
        )
    except lambda_gate.LambdaGateError as exc:
        return PCIResult(
            ok=False,
            reason=f"lambda-invalid:{exc}",
            energy=energy_label,
            signed=signed,
        )

    recorded = lv.get("lambda")
    if isinstance(recorded, bool) or not isinstance(recorded, (int, float)):
        return PCIResult(
            ok=False, reason="lambda-missing", energy=energy_label, signed=signed
        )
    if not math.isclose(
        recomputed, float(recorded), rel_tol=0.0, abs_tol=LAMBDA_RECOMPUTE_TOL
    ):
        return PCIResult(
            ok=False,
            reason="lambda-recompute-mismatch",
            lambda_value=recomputed,
            energy=energy_label,
            signed=signed,
        )

    theta = lv.get("theta")
    if isinstance(theta, bool) or not isinstance(theta, (int, float)):
        return PCIResult(
            ok=False,
            reason="theta-missing",
            lambda_value=recomputed,
            energy=energy_label,
            signed=signed,
        )
    expected = "advisory-pass" if recomputed >= float(theta) else "advisory-fail"
    if lv.get("verdict") != expected:
        return PCIResult(
            ok=False,
            reason="lambda-verdict-inconsistent",
            advisory=expected,
            lambda_value=recomputed,
            energy=energy_label,
            signed=signed,
        )

    return PCIResult(
        ok=True,
        reason=f"ok:{expected}",
        advisory=expected,
        lambda_value=recomputed,
        energy=energy_label,
        signed=signed,
    )
