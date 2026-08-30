# SPDX-License-Identifier: Apache-2.0
"""Fail-closed multi-subject GovernedAction attestations.

This module emits a standards-shaped in-toto Statement inside a DSSE envelope.
It binds every release plane needed to admit a governed action and independently
recomputes the admission result during verification. A producer-provided PASS is
never trusted on its own.

Migration (v11 §7.1 / B-08): the Statement is structurally validated through
the pinned ``in-toto-attestation`` 0.9.3 bindings (:mod:`._intoto`), the DSSE
PAE is the single spec-pinned implementation in :mod:`._canonical` (decimal
lengths over the DECODED payload bytes), and signature arithmetic is the
pinned ``cryptography`` 50.0.1 library (ECDSA P-256). No hand-rolled DSSE or
statement plumbing remains. The predicate type
``https://szl.dev/GovernedAction/v1``, the canonical-JSON payload, the sha256
subject digests, and the standard ``signatures`` array are unchanged.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ._canonical import canonical_json, pae
from ._intoto import STATEMENT_TYPE_URI, statement_ite6_errors

IN_TOTO_STATEMENT_TYPE = STATEMENT_TYPE_URI
GOVERNED_ACTION_PREDICATE_TYPE = "https://szl.dev/GovernedAction/v1"
GOVERNED_ACTION_ENVELOPE_SCHEMA = "https://szl.dev/GovernedActionEnvelope/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

PASS = "PASS"
INCOMPLETE = "INCOMPLETE"
VERIFIED = "VERIFIED"

REQUIRED_SUBJECT_ROLES = (
    "github_source",
    "huggingface_repository",
    "runtime_artifact",
    "deployment",
    "domain",
    "durable_receipt",
    "runtime_witness",
)

_ROLE_DIGEST_ALGORITHM = {
    "github_source": "gitCommit",
    "huggingface_repository": "gitCommit",
    "runtime_artifact": "sha256",
    "deployment": "sha256",
    "domain": "sha256",
    "durable_receipt": "sha256",
    "runtime_witness": "gitCommit",
}
_PREDICATE_FIELDS = {
    "schema",
    "action",
    "actor",
    "policy",
    "subjectRoles",
    "evidence",
    "obligations",
    "sideEffects",
    "assessedAt",
    "signaturePresent",
    "assessment",
}
_HEX_LENGTH = {"gitCommit": 40, "sha256": 64}


@dataclass(frozen=True)
class GovernedActionVerification:
    """Independent verifier result. Only ``status == PASS`` is admissible."""

    status: str
    reasons: tuple[str, ...]
    statement: Optional[dict[str, Any]] = None
    keyid: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status == PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": GOVERNED_ACTION_ENVELOPE_SCHEMA,
            "status": self.status,
            "reasons": list(self.reasons),
            "keyid": self.keyid,
            "statement": self.statement,
        }


# DSSEv1 Pre-Authentication Encoding — the single spec-pinned implementation
# lives in ``_canonical.pae`` (decimal lengths over the DECODED payload bytes).
# This module's pre-migration local copy is deleted (B-08: two divergent PAE
# implementations in one package); the public name is preserved as an alias.
dsse_pae = pae


def _json_copy(value: Any) -> Any:
    return json.loads(canonical_json(value))


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _valid_digest(value: Any, algorithm: str) -> bool:
    length = _HEX_LENGTH[algorithm]
    return isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is not None


def _string_set(value: Any) -> Optional[set[str]]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        return None
    return set(value)


def _public_key_id(public_key: ec.EllipticCurvePublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


def _load_private_key(private_key_pem: bytes | str) -> ec.EllipticCurvePrivateKey:
    raw = private_key_pem.encode("utf-8") if isinstance(private_key_pem, str) else private_key_pem
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("GovernedAction requires an ECDSA P-256 private key")
    return key


def _load_public_key(public_key_pem: bytes | str) -> ec.EllipticCurvePublicKey:
    raw = public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
    key = serialization.load_pem_public_key(raw)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("GovernedAction requires an ECDSA P-256 public key")
    return key


def _strict_json_loads(payload: bytes) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)


def _core_reasons(statement: Any) -> list[str]:
    reasons: list[str] = []
    if not isinstance(statement, Mapping):
        return ["statement-not-object"]
    if statement.get("_type") != IN_TOTO_STATEMENT_TYPE:
        reasons.append("statement-type-invalid")
    if statement.get("predicateType") != GOVERNED_ACTION_PREDICATE_TYPE:
        reasons.append("predicate-type-invalid")

    predicate = statement.get("predicate")
    if not isinstance(predicate, Mapping):
        return sorted(set(reasons + ["predicate-not-object"]))
    if predicate.get("schema") != GOVERNED_ACTION_PREDICATE_TYPE:
        reasons.append("predicate-schema-invalid")
    if predicate.get("signaturePresent") is not True:
        reasons.append("signature-not-present")

    subjects_raw = statement.get("subject")
    subjects = subjects_raw if isinstance(subjects_raw, list) else []
    if not isinstance(subjects_raw, list):
        reasons.append("subjects-not-list")
    by_name: dict[str, Mapping[str, Any]] = {}
    for index, subject in enumerate(subjects):
        if not isinstance(subject, Mapping):
            reasons.append(f"subject-not-object:{index}")
            continue
        if set(subject) != {"name", "digest"}:
            reasons.append(f"subject-fields-not-exact:{index}")
        name = subject.get("name")
        if not isinstance(name, str) or not name:
            reasons.append(f"subject-name-invalid:{index}")
            continue
        if name in by_name:
            reasons.append(f"duplicate-subject-name:{name}")
        else:
            by_name[name] = subject

    roles_raw = predicate.get("subjectRoles")
    roles = roles_raw if isinstance(roles_raw, Mapping) else {}
    if not isinstance(roles_raw, Mapping):
        reasons.append("subject-roles-not-object")
    if set(roles) != set(REQUIRED_SUBJECT_ROLES):
        reasons.append("subject-role-set-mismatch")
    role_names = [value for value in roles.values() if isinstance(value, str)]
    if len(role_names) != len(set(role_names)):
        reasons.append("subject-role-target-duplicate")
    unbound_names = set(by_name) - set(role_names)
    for name in sorted(unbound_names):
        reasons.append(f"unbound-subject:{name}")

    role_digests: dict[str, str] = {}
    for role in REQUIRED_SUBJECT_ROLES:
        target = roles.get(role)
        if not isinstance(target, str) or not target:
            reasons.append(f"missing-subject-role:{role}")
            continue
        subject = by_name.get(target)
        if subject is None:
            reasons.append(f"missing-subject:{role}")
            continue
        algorithm = _ROLE_DIGEST_ALGORITHM[role]
        digest = subject.get("digest")
        if not isinstance(digest, Mapping) or set(digest) != {algorithm}:
            reasons.append(f"subject-digest-shape-invalid:{role}")
            continue
        value = digest.get(algorithm)
        if not _valid_digest(value, algorithm):
            reasons.append(f"subject-digest-invalid:{role}")
            continue
        role_digests[role] = value

    source_values = [
        role_digests.get("github_source"),
        role_digests.get("huggingface_repository"),
        role_digests.get("runtime_witness"),
    ]
    if all(source_values) and len(set(source_values)) != 1:
        reasons.append("contradictory-source-revisions")
    artifact_values = [
        role_digests.get("runtime_artifact"),
        role_digests.get("deployment"),
    ]
    if all(artifact_values) and len(set(artifact_values)) != 1:
        reasons.append("contradictory-artifact-digests")

    assessed_at = _parse_timestamp(predicate.get("assessedAt"))
    if assessed_at is None:
        reasons.append("assessed-at-invalid")

    evidence_raw = predicate.get("evidence")
    evidence = evidence_raw if isinstance(evidence_raw, Mapping) else {}
    if not isinstance(evidence_raw, Mapping):
        reasons.append("evidence-not-object")
    if set(evidence) != set(REQUIRED_SUBJECT_ROLES):
        reasons.append("evidence-role-set-mismatch")
    for role in REQUIRED_SUBJECT_ROLES:
        item = evidence.get(role)
        if not isinstance(item, Mapping):
            reasons.append(f"evidence-missing:{role}")
            continue
        if item.get("status") != VERIFIED:
            reasons.append(f"evidence-not-verified:{role}")
        if not isinstance(item.get("source"), str) or not item.get("source"):
            reasons.append(f"evidence-source-invalid:{role}")
        observed_at = _parse_timestamp(item.get("observedAt"))
        if observed_at is None:
            reasons.append(f"evidence-time-invalid:{role}")
        max_age = item.get("maxAgeSeconds")
        if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age <= 0:
            reasons.append(f"evidence-max-age-invalid:{role}")
        elif assessed_at is not None and observed_at is not None:
            age = (assessed_at - observed_at).total_seconds()
            if age < -300:
                reasons.append(f"evidence-from-future:{role}")
            elif age > max_age:
                reasons.append(f"evidence-stale:{role}")

    actor_raw = predicate.get("actor")
    actor = actor_raw if isinstance(actor_raw, Mapping) else {}
    if not isinstance(actor_raw, Mapping):
        reasons.append("actor-not-object")
    actor_id = actor.get("id")
    if not isinstance(actor_id, str) or not actor_id:
        reasons.append("actor-id-invalid")
    if actor.get("type") not in {"human", "service"}:
        reasons.append("actor-type-invalid")
    if actor.get("authenticated") is not True:
        reasons.append("actor-not-authenticated")

    witness = evidence.get("runtime_witness")
    if isinstance(witness, Mapping):
        if witness.get("independent") is not True:
            reasons.append("runtime-witness-not-independent")
        authority = witness.get("authority")
        if not isinstance(authority, str) or not authority:
            reasons.append("runtime-witness-authority-invalid")
        elif isinstance(actor_id, str) and authority == actor_id:
            reasons.append("runtime-witness-authority-not-independent")

    domain = evidence.get("domain")
    domain_links = _string_set(domain.get("links")) if isinstance(domain, Mapping) else None
    if domain_links is None or "deployment" not in domain_links:
        reasons.append("domain-not-linked-to-deployment")
    durable_receipt = evidence.get("durable_receipt")
    required_receipt_links = set(REQUIRED_SUBJECT_ROLES) - {"durable_receipt"}
    receipt_links = _string_set(
        durable_receipt.get("links") if isinstance(durable_receipt, Mapping) else None
    )
    if receipt_links is None or not required_receipt_links.issubset(receipt_links):
        reasons.append("durable-receipt-links-incomplete")

    action_raw = predicate.get("action")
    action = action_raw if isinstance(action_raw, Mapping) else {}
    if not isinstance(action_raw, Mapping):
        reasons.append("action-not-object")
    for field in ("id", "kind"):
        if not isinstance(action.get(field), str) or not action.get(field):
            reasons.append(f"action-{field}-invalid")
    requested_at = _parse_timestamp(action.get("requestedAt"))
    if requested_at is None:
        reasons.append("action-requested-at-invalid")
    elif assessed_at is not None and requested_at > assessed_at:
        reasons.append("action-requested-after-assessment")

    policy_raw = predicate.get("policy")
    policy = policy_raw if isinstance(policy_raw, Mapping) else {}
    if not isinstance(policy_raw, Mapping):
        reasons.append("policy-not-object")
    if not isinstance(policy.get("id"), str) or not policy.get("id"):
        reasons.append("policy-id-invalid")
    policy_digest = policy.get("digest")
    if (
        not isinstance(policy_digest, Mapping)
        or set(policy_digest) != {"sha256"}
        or not _valid_digest(policy_digest.get("sha256"), "sha256")
    ):
        reasons.append("policy-digest-invalid")
    if policy.get("evaluated") is not True:
        reasons.append("policy-not-evaluated")
    if policy.get("decision") != "ALLOW":
        reasons.append("policy-decision-not-allow")

    obligations = predicate.get("obligations")
    if not isinstance(obligations, list) or not obligations:
        reasons.append("obligations-missing")
    else:
        obligation_ids: set[str] = set()
        for index, obligation in enumerate(obligations):
            if not isinstance(obligation, Mapping):
                reasons.append(f"obligation-not-object:{index}")
                continue
            obligation_id = obligation.get("id")
            if not isinstance(obligation_id, str) or not obligation_id:
                reasons.append(f"obligation-id-invalid:{index}")
            elif obligation_id in obligation_ids:
                reasons.append(f"obligation-id-duplicate:{obligation_id}")
            else:
                obligation_ids.add(obligation_id)
            if obligation.get("status") != "SATISFIED":
                reasons.append(f"obligation-unsatisfied:{obligation_id or index}")
            evidence_subjects = obligation.get("evidenceSubjects")
            if not isinstance(evidence_subjects, list) or not evidence_subjects:
                reasons.append(f"obligation-evidence-missing:{obligation_id or index}")
            elif any(role not in REQUIRED_SUBJECT_ROLES for role in evidence_subjects):
                reasons.append(f"obligation-evidence-invalid:{obligation_id or index}")

    side_effects = predicate.get("sideEffects")
    if not isinstance(side_effects, list):
        reasons.append("side-effects-not-list")
    else:
        effect_ids: set[str] = set()
        for index, effect in enumerate(side_effects):
            if not isinstance(effect, Mapping):
                reasons.append(f"side-effect-not-object:{index}")
                continue
            effect_id = effect.get("id")
            if not isinstance(effect_id, str) or not effect_id:
                reasons.append(f"side-effect-id-invalid:{index}")
            elif effect_id in effect_ids:
                reasons.append(f"side-effect-id-duplicate:{effect_id}")
            else:
                effect_ids.add(effect_id)
            required = effect.get("required")
            status = effect.get("status")
            if not isinstance(required, bool):
                reasons.append(f"side-effect-required-invalid:{effect_id or index}")
            if status not in {"COMPLETED", "NOT_PERFORMED"}:
                reasons.append(f"side-effect-status-invalid:{effect_id or index}")
            if required is True and status != "COMPLETED":
                reasons.append(f"side-effect-required-incomplete:{effect_id or index}")
            if status == "COMPLETED" and effect.get("receiptSubject") != "durable_receipt":
                reasons.append(f"side-effect-receipt-missing:{effect_id or index}")

    return sorted(set(reasons))


def _combined_reasons(statement: Any) -> list[str]:
    """Admission reasons + ITE-6 structural reasons from the pinned library.

    Used identically at build time (to write the honest ``assessment``) and at
    verify time (to recompute it), so a producer-stated assessment that
    disagrees with the independent recomputation is caught by
    ``assessment-reasons-mismatch`` / ``assessment-status-mismatch``.
    """

    return sorted(set(_core_reasons(statement) + statement_ite6_errors(statement)))


def _assessment_reasons(statement: Any, core_reasons: Sequence[str]) -> list[str]:
    if not isinstance(statement, Mapping):
        return []
    predicate = statement.get("predicate")
    if not isinstance(predicate, Mapping):
        return []
    reasons: list[str] = []
    if set(predicate) != _PREDICATE_FIELDS:
        reasons.append("predicate-fields-not-exact")
    assessment = predicate.get("assessment")
    if not isinstance(assessment, Mapping):
        return reasons + ["assessment-not-object"]
    if set(assessment) != {"status", "reasons"}:
        reasons.append("assessment-fields-not-exact")
    expected_status = PASS if not core_reasons else INCOMPLETE
    if assessment.get("status") != expected_status:
        reasons.append("assessment-status-mismatch")
    stated_reasons = assessment.get("reasons")
    if not isinstance(stated_reasons, list) or stated_reasons != list(core_reasons):
        reasons.append("assessment-reasons-mismatch")
    return reasons


def build_governed_action_statement(
    *,
    action: Mapping[str, Any],
    actor: Mapping[str, Any],
    policy: Mapping[str, Any],
    subjects: Sequence[Mapping[str, Any]],
    subject_roles: Mapping[str, str],
    evidence: Mapping[str, Mapping[str, Any]],
    obligations: Sequence[Mapping[str, Any]],
    side_effects: Sequence[Mapping[str, Any]] = (),
    assessed_at: str,
    signature_present: bool = False,
) -> dict[str, Any]:
    """Build a deterministic GovernedAction Statement and signed assessment.

    ``signature_present`` must only be true when the returned statement will be
    covered by a real DSSE signature. The high-level emitter sets it safely.
    """

    predicate: dict[str, Any] = {
        "schema": GOVERNED_ACTION_PREDICATE_TYPE,
        "action": _json_copy(action),
        "actor": _json_copy(actor),
        "policy": _json_copy(policy),
        "subjectRoles": _json_copy(subject_roles),
        "evidence": _json_copy(evidence),
        "obligations": _json_copy(list(obligations)),
        "sideEffects": _json_copy(list(side_effects)),
        "assessedAt": assessed_at,
        "signaturePresent": signature_present is True,
    }
    statement: dict[str, Any] = {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": _json_copy(list(subjects)),
        "predicateType": GOVERNED_ACTION_PREDICATE_TYPE,
        "predicate": predicate,
    }
    reasons = _combined_reasons(statement)
    predicate["assessment"] = {
        "status": PASS if not reasons else INCOMPLETE,
        "reasons": reasons,
    }
    return statement


def emit_governed_action(
    *,
    action: Mapping[str, Any],
    actor: Mapping[str, Any],
    policy: Mapping[str, Any],
    subjects: Sequence[Mapping[str, Any]],
    subject_roles: Mapping[str, str],
    evidence: Mapping[str, Mapping[str, Any]],
    obligations: Sequence[Mapping[str, Any]],
    side_effects: Sequence[Mapping[str, Any]] = (),
    assessed_at: str,
    private_key_pem: Optional[bytes | str] = None,
) -> dict[str, Any]:
    """Emit one standard DSSE envelope containing one GovernedAction Statement."""

    statement = build_governed_action_statement(
        action=action,
        actor=actor,
        policy=policy,
        subjects=subjects,
        subject_roles=subject_roles,
        evidence=evidence,
        obligations=obligations,
        side_effects=side_effects,
        assessed_at=assessed_at,
        signature_present=private_key_pem is not None,
    )
    payload = canonical_json(statement)
    envelope: dict[str, Any] = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [],
    }
    if private_key_pem is None:
        return envelope

    private_key = _load_private_key(private_key_pem)
    signature = private_key.sign(
        dsse_pae(DSSE_PAYLOAD_TYPE, payload), ec.ECDSA(hashes.SHA256())
    )
    envelope["signatures"] = [
        {
            "keyid": _public_key_id(private_key.public_key()),
            "sig": base64.b64encode(signature).decode("ascii"),
        }
    ]
    return envelope


def verify_governed_action(
    envelope: Any,
    public_key_pem: Optional[bytes | str] = None,
    *,
    expected_keyid: Optional[str] = None,
) -> GovernedActionVerification:
    """Independently verify DSSE authenticity and every admission invariant."""

    reasons: list[str] = []
    statement: Optional[dict[str, Any]] = None
    keyid: Optional[str] = None

    if not isinstance(envelope, Mapping):
        return GovernedActionVerification(INCOMPLETE, ("envelope-not-object",))
    if set(envelope) != {"payloadType", "payload", "signatures"}:
        reasons.append("envelope-fields-not-exact")
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        reasons.append("payload-type-invalid")

    payload: Optional[bytes] = None
    encoded_payload = envelope.get("payload")
    if not isinstance(encoded_payload, str):
        reasons.append("payload-not-string")
    else:
        try:
            payload = base64.b64decode(encoded_payload, validate=True)
            decoded = _strict_json_loads(payload)
            if isinstance(decoded, dict):
                statement = decoded
            else:
                reasons.append("statement-not-object")
            if canonical_json(decoded) != payload:
                reasons.append("payload-not-canonical-json")
        except Exception:  # malformed input is evidence failure, never an exception
            reasons.append("payload-decode-invalid")

    signatures = envelope.get("signatures")
    if not isinstance(signatures, list):
        reasons.append("signatures-not-list")
        signatures = []
    if len(signatures) != 1:
        reasons.append("dsse-signature-count-not-one")
    elif not isinstance(signatures[0], Mapping):
        reasons.append("dsse-signature-not-object")
    else:
        signature_entry = signatures[0]
        if set(signature_entry) != {"keyid", "sig"}:
            reasons.append("dsse-signature-fields-not-exact")
        keyid_value = signature_entry.get("keyid")
        keyid = keyid_value if isinstance(keyid_value, str) else None
        if not keyid:
            reasons.append("keyid-invalid")
        if expected_keyid is not None and keyid != expected_keyid:
            reasons.append("keyid-unexpected")
        if public_key_pem is None:
            reasons.append("public-key-required")
        elif payload is not None:
            try:
                public_key = _load_public_key(public_key_pem)
                derived_keyid = _public_key_id(public_key)
                if keyid != derived_keyid:
                    reasons.append("keyid-public-key-mismatch")
                encoded_signature = signature_entry.get("sig")
                if not isinstance(encoded_signature, str):
                    reasons.append("signature-not-string")
                else:
                    signature = base64.b64decode(encoded_signature, validate=True)
                    public_key.verify(
                        signature,
                        dsse_pae(DSSE_PAYLOAD_TYPE, payload),
                        ec.ECDSA(hashes.SHA256()),
                    )
            except InvalidSignature:
                reasons.append("signature-mismatch")
            except Exception:
                reasons.append("signature-or-key-invalid")

    core = _combined_reasons(statement)
    reasons.extend(core)
    reasons.extend(_assessment_reasons(statement, core))
    final_reasons = tuple(sorted(set(reasons)))
    return GovernedActionVerification(
        PASS if not final_reasons else INCOMPLETE,
        final_reasons,
        statement,
        keyid,
    )


__all__ = [
    "DSSE_PAYLOAD_TYPE",
    "GOVERNED_ACTION_ENVELOPE_SCHEMA",
    "GOVERNED_ACTION_PREDICATE_TYPE",
    "INCOMPLETE",
    "PASS",
    "REQUIRED_SUBJECT_ROLES",
    "VERIFIED",
    "GovernedActionVerification",
    "build_governed_action_statement",
    "dsse_pae",
    "emit_governed_action",
    "verify_governed_action",
]
