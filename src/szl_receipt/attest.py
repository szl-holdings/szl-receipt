# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""
Standards-interop + compliance-evidence attestation — the ONE shared home.

Every SZL component that emits an honest, hash-chained receipt
(governed-inference-meter, szl-energy-attest, ...) can render that receipt as
an attestation the wider ecosystem already understands, and map it onto the
regulatory controls it provides operational evidence for — WITHOUT each
package re-implementing (and drifting) the ecosystem shapes or the regulator
catalogue. This module is that single source of truth.

What lives here (all schema-agnostic):
  * :func:`build_statement` — wrap a subject digest + predicate as an
    **in-toto Statement v1** (the payload Sigstore / DSSE / IETF SCITT tooling
    already carries, signs, and logs).
  * :func:`slsa_predicate` — the SLSA-v1-*shaped* predicate skeleton
    (``buildDefinition`` / ``runDetails``) so an auditor recognizes it on sight.
  * :data:`CONTROLS` + :func:`compliance_evidence` — the canonical **EU AI Act**
    / **NIST AI RMF** control catalogue and the honest capability->control map.
  * :func:`verify_statement` — a generic check that a Statement's subject is
    bound to an expected receipt digest.

Each emitting package computes ITS OWN receipt body digest and a small set of
capability flags (which of ``logging`` / ``integrity`` / ``energy`` /
``governance`` the receipt honestly provides), then delegates here.

HONESTY DOCTRINE (identical to the receipt core — never weakened):
  * ``predicateType`` is an SZL URI, SLSA-*shaped* for recognizability — it is
    NEVER a claim of official SLSA-provenance conformance.
  * A receipt is EVIDENCE toward a control, never a conformity assessment,
    certification, or safety guarantee. Every catalogue entry carries an
    explicit ``does_not_establish`` note; the bundle carries a disclaimer.
  * Energy-dependent controls resolve to ``UNAVAILABLE`` whenever the emitter
    reports no measured energy — a joule is never fabricated, here or anywhere.
  * Pure stdlib (json via ``_canonical``). Nothing is written to disk or the
    network; signing is the separate, out-of-band concern of ``sign_receipt``.
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ._canonical import canonical_json

# In-toto Statement envelope type (stable, ecosystem-standard URI).
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# Default SZL predicate type. Honest: an SZL URI, SLSA-*shaped* for
# recognizability — NOT a claim of official SLSA-provenance conformance.
# Emitters typically pass their OWN per-product predicate type instead.
DEFAULT_PREDICATE_TYPE = "https://a-11-oy.com/attest/szl-receipt/v0.1"

UNAVAILABLE = "UNAVAILABLE"

# The capability "kinds" a receipt may provide operational evidence for.
KIND_LOGGING = "logging"
KIND_INTEGRITY = "integrity"
KIND_ENERGY = "energy"
KIND_GOVERNANCE = "governance"

DISCLAIMER = (
    "This is machine-readable EVIDENCE toward the listed controls, not a "
    "conformity assessment, certification, or safety guarantee. A receipt "
    "documents what happened; it does not by itself make a system compliant."
)

# --- Compliance control catalogue -----------------------------------------
# Each entry states, in product-neutral terms, what an honest hash-chained SZL
# receipt provides evidence for (``establishes``) and — doctrine-critical —
# what it does NOT establish. ``kind`` selects which caller capability gates it.
CONTROLS: List[Dict[str, str]] = [
    {
        "id": "EU-AI-Act-Art-12",
        "title": "Record-keeping — automatic recording of events (logs)",
        "kind": KIND_LOGGING,
        "establishes": (
            "Each governed event is automatically recorded in a tamper-evident, "
            "hash-chained log — automatic event logging over the system's "
            "operation."
        ),
        "does_not_establish": (
            "Does not itself define log retention duration or the risk-management "
            "system those logs feed; that is an operator responsibility."
        ),
    },
    {
        "id": "EU-AI-Act-Art-19",
        "title": "Automatically generated logs — availability & integrity",
        "kind": KIND_LOGGING,
        "establishes": (
            "The hash chain makes any post-hoc edit or reordering of the retained "
            "logs detectable, so logs are demonstrably intact when produced."
        ),
        "does_not_establish": (
            "Does not enforce the retention period or storage of the logs; the "
            "chain proves integrity, not that logs were kept for the required time."
        ),
    },
    {
        "id": "EU-AI-Act-Art-15",
        "title": "Accuracy, robustness and cybersecurity",
        "kind": KIND_INTEGRITY,
        "establishes": (
            "Tamper-evidence contributes to record integrity / resistance to log "
            "manipulation (a cybersecurity-relevant property)."
        ),
        "does_not_establish": (
            "Does NOT establish model accuracy or robustness — it says nothing "
            "about the correctness of the model's outputs."
        ),
    },
    {
        "id": "NIST-AI-RMF-MEASURE-2.x",
        "title": "MEASURE — track quantitative metrics (energy / efficiency)",
        "kind": KIND_ENERGY,
        "establishes": (
            "Measured energy (e.g. GPU joules) is recorded per event, giving an "
            "auditable quantitative energy/efficiency metric."
        ),
        "does_not_establish": (
            "When energy is unmeasured no efficiency claim is made; and the metric "
            "measures cost/energy, not model quality or safety."
        ),
    },
    {
        "id": "NIST-AI-RMF-MANAGE-4.1",
        "title": "MANAGE — post-deployment monitoring & logging",
        "kind": KIND_LOGGING,
        "establishes": (
            "A continuous, verifiable per-event log supports ongoing monitoring of "
            "a deployed system's activity and governance decisions."
        ),
        "does_not_establish": (
            "Does not define incident response or remediation; it is the "
            "monitoring substrate, not the management process itself."
        ),
    },
    {
        "id": "NIST-AI-RMF-GOVERN-1.x",
        "title": "GOVERN — documented, auditable governance decisions",
        "kind": KIND_GOVERNANCE,
        "establishes": (
            "The recorded governance decision and its reason document the decision "
            "made alongside each event."
        ),
        "does_not_establish": (
            "A recorded decision is not proof the decision was enforced by the "
            "runtime; enforcement is a host responsibility."
        ),
    },
]


def build_statement(
    *,
    subject_name: str,
    subject_digest: str,
    predicate: Dict[str, Any],
    predicate_type: str = DEFAULT_PREDICATE_TYPE,
    digest_alg: str = "sha256",
) -> Dict[str, Any]:
    """Wrap *predicate* as an in-toto Statement v1 bound to *subject_digest*.

    The single subject is the receipt, identified by its content digest, so the
    attestation is inseparable from the exact record it describes. The returned
    dict is the *unsigned* payload a DSSE/Sigstore signer would then wrap.

    Args:
        subject_name: Human/tool-facing name for the subject (the receipt).
        subject_digest: Hex digest of the receipt body (the binding anchor).
        predicate: The predicate object (see :func:`slsa_predicate`).
        predicate_type: Predicate type URI (SZL-owned; SLSA-shaped, not a
            conformance claim).
        digest_alg: Digest algorithm label for the subject (default sha256).

    Returns:
        An in-toto Statement v1 dict.
    """
    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [{"name": subject_name, "digest": {digest_alg: subject_digest}}],
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def slsa_predicate(
    *,
    build_type: str,
    external_parameters: Optional[Mapping[str, Any]] = None,
    internal_parameters: Optional[Mapping[str, Any]] = None,
    builder_id: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Assemble a SLSA-v1-*shaped* provenance predicate skeleton.

    Emitters fill ``external_parameters`` / ``internal_parameters`` / ``metadata``
    from their own receipt schema. ``extra`` is merged at the predicate's top
    level (e.g. a ``doctrine`` note). This centralizes the SLSA shape so callers
    never hand-roll (and drift) the ``buildDefinition`` / ``runDetails`` nesting.
    """
    predicate: Dict[str, Any] = {
        "buildDefinition": {
            "buildType": build_type,
            "externalParameters": dict(external_parameters or {}),
            "internalParameters": dict(internal_parameters or {}),
        },
        "runDetails": {
            "builder": {"id": builder_id or build_type},
            "metadata": dict(metadata or {}),
        },
    }
    if extra:
        predicate.update(dict(extra))
    return predicate


def compliance_evidence(
    *,
    capabilities: Mapping[str, bool],
    subject_digest: Optional[str] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Map a receipt's *capabilities* onto the EU AI Act / NIST AI RMF catalogue.

    Args:
        capabilities: Which capability *kinds* the receipt honestly provides,
            e.g. ``{"logging": True, "integrity": True, "governance": True,
            "energy": measured}``. A control whose ``kind`` is absent/False is
            reported ``UNAVAILABLE`` (never silently "supports").
        subject_digest: Optional receipt digest, echoed for traceability.
        extra: Optional extra top-level fields merged into the returned bundle
            (e.g. emitter-specific ``doctrine`` / receipt identifiers).

    Returns:
        A bundle dict with per-control ``status`` (``"supports"`` or
        ``UNAVAILABLE``), each carrying an explicit ``does_not_establish`` note,
        plus a ``disclaimer``. EVIDENCE — never a conformity assessment.
    """
    caps = dict(capabilities or {})
    controls: List[Dict[str, Any]] = []
    for c in CONTROLS:
        if caps.get(c["kind"], False):
            status, evidence = "supports", c["establishes"]
        elif c["kind"] == KIND_ENERGY:
            status = UNAVAILABLE
            evidence = "energy unmeasured on this receipt — no efficiency evidence"
        else:
            status = UNAVAILABLE
            evidence = "capability not provided by this receipt"
        controls.append(
            {
                "id": c["id"],
                "title": c["title"],
                "status": status,
                "evidence": evidence,
                "does_not_establish": c["does_not_establish"],
            }
        )
    bundle: Dict[str, Any] = {
        "subject_digest": subject_digest,
        "measured_energy": bool(caps.get(KIND_ENERGY, False)),
        "controls": controls,
        "disclaimer": DISCLAIMER,
    }
    if extra:
        bundle.update(dict(extra))
    return bundle


def verify_statement(
    statement: Dict[str, Any],
    *,
    expected_digest: str,
    predicate_type: Optional[str] = None,
    digest_alg: str = "sha256",
) -> Tuple[bool, str]:
    """Confirm *statement* is a valid in-toto Statement bound to *expected_digest*.

    Args:
        statement: The Statement dict (as from :func:`build_statement`).
        expected_digest: The digest the caller has independently re-derived from
            the receipt it holds. The subject MUST carry this digest.
        predicate_type: If given, the Statement's ``predicateType`` must match.
        digest_alg: Digest algorithm label to read from the subject.

    Returns:
        ``(True, "ok")`` or ``(False, "<reason>")``. Never raises on a
        malformed statement — a bad shape is a graceful ``False``.
    """
    if not isinstance(statement, dict):
        return (False, "not-a-statement")
    if statement.get("_type") != IN_TOTO_STATEMENT_TYPE:
        return (False, "not-an-intoto-statement")
    if predicate_type is not None and statement.get("predicateType") != predicate_type:
        return (False, "unexpected-predicate-type")
    subjects = statement.get("subject") or []
    if not isinstance(subjects, Sequence):
        return (False, "no-subject")
    subj_digests = [
        s.get("digest", {}).get(digest_alg)
        for s in subjects
        if isinstance(s, dict)
    ]
    if expected_digest not in subj_digests:
        return (False, "subject-digest-not-bound")
    return (True, "ok")


def to_json(obj: Any) -> str:
    """Canonical (sorted, compact) JSON — the bytes a DSSE signer would cover."""
    return canonical_json(obj).decode("utf-8")
