# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""
Bridge to the pinned in-toto Attestation Framework bindings.

The v11 doctrine (§7.1, contradiction B-08) locks the attestation layer to
the maintained PyPI package ``in-toto-attestation`` 0.9.3 (maintainers
adityasaky, lukpueh) and forbids hand-rolled DSSE/statement plumbing. The
package ships the ITE-6 protobuf bindings —
``in_toto_attestation.v1.statement`` and
``in_toto_attestation.v1.resource_descriptor`` — and, by design, no DSSE
envelope code (verified by inspection of the 0.9.3 wheel). The DSSE
transport therefore stays in :mod:`._canonical` (spec-pinned PAE) and the
signature arithmetic in the pinned ``cryptography`` 50.0.1 (ECDSA P-256).

Every in-toto Statement this package emits is constructed and validated
through :func:`statement_from_parts`, so the ITE-6 minimums — the v1 type
URI, at least one subject, a digest on every subject, a predicate type, a
non-empty predicate — are enforced by the maintained library instead of by
hand-checked convention.

Byte-stability note: a protobuf ``Struct`` round-trip renders integral JSON
numbers as floats (``3600`` becomes ``3600.0``), which would change the
canonical payload bytes and silently break digest stability and every
previously computed subject binding. Statements are therefore serialised
from the caller's validated mapping with :func:`._canonical.canonical_json`;
the protobuf layer is the validation authority, not the serialiser.
"""
from __future__ import annotations

from typing import Any, List, Mapping, Sequence

from in_toto_attestation.v1.resource_descriptor import ResourceDescriptor
from in_toto_attestation.v1.statement import STATEMENT_TYPE_URI, Statement

__all__ = ["STATEMENT_TYPE_URI", "statement_from_parts", "statement_ite6_errors"]


def statement_from_parts(
    *,
    subjects: Sequence[Mapping[str, Any]],
    predicate_type: str,
    predicate: Mapping[str, Any],
) -> Statement:
    """Build and validate an in-toto Statement v1 through the pinned bindings.

    Args:
        subjects: Sequence of ``{"name": str, "digest": {alg: hex}}``
            resource-descriptor mappings. At least one required; each must
            carry a non-empty name and at least one digest.
        predicate_type: Predicate type URI (e.g.
            ``https://szl.dev/GovernedAction/v1``). Required.
        predicate: JSON-serialisable predicate mapping. Must be non-empty.

    Returns:
        The validated :class:`in_toto_attestation.v1.statement.Statement`.

    Raises:
        ValueError: On any ITE-6 structural violation (missing subjects,
            missing digests, empty predicate type, empty predicate, ...).
        TypeError: If the predicate is not JSON-representable.
    """
    if not isinstance(predicate_type, str) or not predicate_type:
        raise ValueError("predicate_type must be a non-empty string")
    if not isinstance(predicate, Mapping) or not predicate:
        raise ValueError("predicate must be a non-empty mapping")
    if (
        not isinstance(subjects, Sequence)
        or isinstance(subjects, (str, bytes))
        or not subjects
    ):
        raise ValueError("subjects must be a non-empty sequence of mappings")
    descriptors: List[Any] = []
    for index, subject in enumerate(subjects):
        if not isinstance(subject, Mapping):
            raise ValueError(f"subject {index} must be a mapping")
        name = subject.get("name")
        digest = subject.get("digest")
        if not isinstance(name, str) or not name:
            raise ValueError(f"subject {index} requires a non-empty name")
        if not isinstance(digest, Mapping) or not digest:
            raise ValueError(f"subject {index} requires at least one digest")
        descriptor = ResourceDescriptor(
            name=name,
            digest={str(alg): str(value) for alg, value in digest.items()},
        )
        descriptor.validate()
        descriptors.append(descriptor.pb)
    statement = Statement(
        subjects=descriptors,
        predicate_type=predicate_type,
        predicate=dict(predicate),
    )
    statement.validate()
    return statement


def statement_ite6_errors(statement: Any) -> List[str]:
    """Fail-soft ITE-6 structural validation of a statement mapping.

    Args:
        statement: The candidate in-toto Statement as a plain mapping (as
            decoded from a DSSE payload or assembled by a builder).

    Returns:
        ``[]`` when the mapping constructs and validates cleanly through the
        pinned in-toto-attestation bindings, otherwise a single
        ``statement-ite6-invalid:<detail>`` reason. Never raises — the
        GovernedAction honest-INCOMPLETE contract depends on structural
        failures being reported as reasons, not exceptions.
    """
    if not isinstance(statement, Mapping):
        return ["statement-ite6-invalid: statement is not a mapping"]
    if statement.get("_type") != STATEMENT_TYPE_URI:
        return [f"statement-ite6-invalid: _type is not {STATEMENT_TYPE_URI}"]
    subjects = statement.get("subject")
    predicate = statement.get("predicate")
    try:
        statement_from_parts(
            subjects=subjects if isinstance(subjects, list) else [],
            predicate_type=statement.get("predicateType") or "",
            predicate=predicate if isinstance(predicate, Mapping) else {},
        )
    except (ValueError, TypeError) as exc:
        return [f"statement-ite6-invalid: {exc}"]
    return []
