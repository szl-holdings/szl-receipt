# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""
PCGI SDK — the one-call unifier for Proof-Carrying Governed Intelligence.

Any model or agent (a11oy, killinchu, yarqa, david-leads, ...) calls a SINGLE
function, :func:`emit_receipt`, to produce ONE signed receipt that binds, in a
single tamper-evident record:

  * ``model_id``       — which model produced the decision,
  * ``input_digest``   — the digest of the input it saw,
  * ``output_digest``  — the digest of the output it produced,
  * ``policy_id``      — the governing policy under which it acted,
  * measured ``energy``— joules VERBATIM when measured, or the honest string
    ``"UNAVAILABLE"`` when not — a joule is NEVER fabricated,
  * optional BFT ``witnesses`` — co-signing witnesses, stored verbatim.

The output reuses the EXISTING, battle-tested shapes — it does not re-implement
or fork them:

  * ``envelope``   — the cosign-compatible DSSE envelope from
    :func:`szl_receipt.receipt.sign_receipt` (verifiable by the existing
    :func:`szl_receipt.receipt.verify_receipt` with zero changes),
  * ``statement``  — the in-toto Statement v1 from
    :func:`szl_receipt.attest.build_statement` bound to the same body digest,
  * ``compliance`` — the EU AI Act / NIST AI RMF evidence bundle from
    :func:`szl_receipt.attest.compliance_evidence`.

HONESTY DOCTRINE (never weakened):
  * A receipt is EVIDENCE of what happened — a signed binding of
    model+input+output+policy(+energy)(+witnesses). It is NOT a claim that the
    decision was correct, nor a conformity assessment or safety guarantee.
  * Energy is measured-or-``UNAVAILABLE``. Fabricating a joule value (including
    coercing a bool/None/garbage into a number) is rejected outright.
  * Keyless emission stays UNSIGNED-honest: the envelope is honestly unsigned and
    :func:`verify_receipt` reports ``unsigned-honest``, never a fake pass.
  * Deterministic: identical inputs produce a byte-identical canonical body (and
    therefore an identical digest and payload). Only the ECDSA signature — which
    carries a random nonce by construction — differs between two signings.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from ._canonical import canonical_json
from .attest import (
    UNAVAILABLE,
    build_statement,
    compliance_evidence,
    slsa_predicate,
    verify_statement,
)
from .receipt import Receipt, sign_receipt
from .receipt import verify_receipt as _verify_envelope

#: Schema tag for a PCGI receipt body (the canonical bound record).
PCGI_SCHEMA = "https://a-11-oy.com/pcgi/receipt/v1"

#: Default in-toto predicate type for a PCGI inference receipt. Honest: an SZL
#: URI, SLSA-*shaped* for recognizability — NOT an SLSA-conformance claim.
PCGI_PREDICATE_TYPE = "https://a-11-oy.com/attest/pcgi-inference/v0.1"

#: Default SLSA-shaped buildType for the governed-inference predicate.
PCGI_BUILD_TYPE = "https://a-11-oy.com/pcgi/governed-inference/v1"

#: The doctrine note carried alongside every emitted receipt.
DOCTRINE = (
    "This receipt is EVIDENCE: a signed binding of model, input, output and "
    "governing policy (with measured-or-UNAVAILABLE energy and optional BFT "
    "witnesses). It does NOT assert the decision is correct, nor is it a "
    "conformity assessment, certification, or safety guarantee."
)


def _energy_field(energy_joules: Optional[float]) -> Any:
    """Render the energy binding — measured joules verbatim, or UNAVAILABLE.

    Honest doctrine: ``None`` means unmeasured and resolves to the string
    ``"UNAVAILABLE"``. A measured value is stored VERBATIM (no rounding, no
    coercion). A ``bool`` or any non-real-number is REJECTED — a joule is never
    fabricated from a truthy flag or garbage.
    """
    if energy_joules is None:
        return UNAVAILABLE
    if isinstance(energy_joules, bool) or not isinstance(energy_joules, (int, float)):
        raise ValueError(
            "energy_joules must be a real number of joules or None "
            "(honest UNAVAILABLE) — never fabricated"
        )
    return {"joules": energy_joules, "unit": "J"}


def emit_receipt(
    *,
    model_id: str,
    input_digest: str,
    output_digest: str,
    policy_id: str,
    energy_joules: Optional[float] = None,
    witnesses: Optional[Sequence[Any]] = None,
    kind: str = "governed.inference",
    organ: str = "unknown",
    private_key_pem: Optional[str | bytes] = None,
    keyid: str = "",
    predicate_type: str = PCGI_PREDICATE_TYPE,
    build_type: str = PCGI_BUILD_TYPE,
    subject_name: Optional[str] = None,
    lean_guarantee: Optional[str] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Emit ONE signed PCGI receipt binding a governed decision.

    This is the single high-level call the other decision producers adopt. It
    assembles the canonical bound body, signs it (or stays UNSIGNED-honest when
    keyless), and renders the ecosystem-standard in-toto Statement plus the
    EU AI Act / NIST AI RMF evidence bundle — all over the SAME body digest so
    the three artifacts are inseparable.

    Args:
        model_id: Identifier of the model that produced the decision.
        input_digest: Digest of the input the model saw (caller-computed).
        output_digest: Digest of the output the model produced (caller-computed).
        policy_id: Identifier of the governing policy under which it acted.
        energy_joules: Measured energy in joules (stored verbatim), or ``None``
            for honest ``UNAVAILABLE``. Never fabricated.
        witnesses: Optional sequence of BFT witnesses (stored verbatim).
        kind: Receipt kind label (default ``"governed.inference"``).
        organ: Logical signing authority label (e.g. ``"a11oy"``).
        private_key_pem: PEM ECDSA-P256 private key, or ``None`` for keyless
            (UNSIGNED-honest) emission.
        keyid: Optional key identifier string.
        predicate_type: in-toto predicateType URI (SZL-owned; SLSA-shaped).
        build_type: SLSA-shaped buildType URI for the predicate.
        subject_name: Optional subject name; defaults to ``receipt/<model_id>``.
        lean_guarantee: Optional name of a formal (Lean) guarantee to bind.
            Honest: this records WHICH guarantee is referenced; it does not by
            itself prove anything.
        extra: Optional caller fields, nested under ``body["extra"]`` so they
            can never clobber the bound fields.

    Returns:
        A composite dict with keys ``schema``, ``digest``, ``body``,
        ``envelope`` (cosign-compatible DSSE), ``statement`` (in-toto v1) and
        ``compliance`` (evidence bundle).
    """
    energy = _energy_field(energy_joules)
    witness_list = list(witnesses or [])

    body: Dict[str, Any] = {
        "schema": PCGI_SCHEMA,
        "kind": kind,
        "model_id": model_id,
        "input_digest": input_digest,
        "output_digest": output_digest,
        "policy_id": policy_id,
        "energy": energy,
        "witnesses": witness_list,
    }
    if lean_guarantee is not None:
        body["lean_guarantee"] = lean_guarantee
    if extra:
        body["extra"] = dict(extra)

    receipt = Receipt(kind=kind, body=body)
    digest = receipt.digest()
    envelope = sign_receipt(
        receipt, private_key_pem=private_key_pem, organ=organ, keyid=keyid
    )

    predicate = slsa_predicate(
        build_type=build_type,
        external_parameters={
            "model_id": model_id,
            "input_digest": input_digest,
            "policy_id": policy_id,
        },
        internal_parameters={},
        builder_id=organ,
        metadata={
            "output_digest": output_digest,
            "energy": energy,
            "witness_count": len(witness_list),
        },
        extra={"doctrine": DOCTRINE},
    )
    statement = build_statement(
        subject_name=subject_name or f"receipt/{model_id}",
        subject_digest=digest,
        predicate=predicate,
        predicate_type=predicate_type,
    )

    compliance = compliance_evidence(
        capabilities={
            "logging": True,
            "integrity": True,
            "governance": True,
            "energy": energy_joules is not None,
        },
        subject_digest=digest,
        extra={"doctrine": DOCTRINE, "signed": envelope["signed"]},
    )

    return {
        "schema": PCGI_SCHEMA,
        "digest": digest,
        "body": body,
        "envelope": envelope,
        "statement": statement,
        "compliance": compliance,
    }


def verify_receipt(
    receipt: Dict[str, Any],
    public_key_pem: Optional[str | bytes] = None,
    *,
    predicate_type: Optional[str] = None,
) -> Tuple[bool, str]:
    """Verify a composite receipt produced by :func:`emit_receipt`.

    Convenience wrapper over the existing primitives. It confirms the three
    artifacts are internally consistent (body ↔ payload ↔ digest ↔ statement
    subject) and then delegates the authenticity verdict to the existing
    envelope verifier — so the UNSIGNED-honest contract is preserved (a keyless
    receipt returns ``(False, "unsigned-honest")``, never a fake pass).

    Args:
        receipt: The composite dict from :func:`emit_receipt`.
        public_key_pem: PEM ECDSA-P256 public key (required for a signed
            envelope; ignored for unsigned).
        predicate_type: If given, the in-toto Statement's ``predicateType`` must
            match.

    Returns:
        ``(True, "ok")`` when the binding holds AND the signature verifies.
        ``(False, "<reason>")`` otherwise. Never raises on a malformed input.
    """
    if not isinstance(receipt, dict):
        return (False, "not-a-receipt")

    envelope = receipt.get("envelope")
    if not isinstance(envelope, dict):
        return (False, "no-envelope")

    try:
        payload_bytes = base64.b64decode(envelope["payload"])
    except Exception as exc:  # noqa: BLE001
        return (False, f"envelope-decode-error: {exc}")

    redigest = hashlib.sha256(payload_bytes).hexdigest()

    body = receipt.get("body")
    if body is not None and canonical_json(body) != payload_bytes:
        return (False, "body-payload-mismatch")

    composite_digest = receipt.get("digest")
    if composite_digest is not None and composite_digest != redigest:
        return (False, "digest-mismatch")

    env_digest = envelope.get("digest")
    if env_digest is not None and env_digest != redigest:
        return (False, "envelope-digest-mismatch")

    statement = receipt.get("statement")
    if statement is not None:
        ok_s, why_s = verify_statement(
            statement, expected_digest=redigest, predicate_type=predicate_type
        )
        if not ok_s:
            return (False, f"statement-{why_s}")

    return _verify_envelope(envelope, public_key_pem)
