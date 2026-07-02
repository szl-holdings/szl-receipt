# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
"""Tests for the shared standards-interop + compliance-evidence layer.

Schema-agnostic: these exercise the shared shapes directly with a synthetic
receipt digest, proving the in-toto Statement binding, the SLSA-shaped
predicate skeleton, the EU AI Act / NIST AI RMF catalogue honesty, and that
energy-dependent evidence honestly degrades to UNAVAILABLE.
"""
import hashlib
import json

from szl_receipt import attest


def _digest(body):
    from szl_receipt._canonical import canonical_json
    return hashlib.sha256(canonical_json(body)).hexdigest()


def test_build_statement_and_verify_binding():
    dg = _digest({"seq": 1, "model": "m"})
    pred = attest.slsa_predicate(
        build_type="https://example.test/pred/v1",
        external_parameters={"model": "m"},
        metadata={"measured": False},
        extra={"doctrine": "evidence not conformity"},
    )
    stmt = attest.build_statement(
        subject_name="receipt/seq-1",
        subject_digest=dg,
        predicate=pred,
        predicate_type="https://example.test/pred/v1",
    )
    assert stmt["_type"] == attest.IN_TOTO_STATEMENT_TYPE
    assert stmt["subject"][0]["digest"]["sha256"] == dg
    assert stmt["predicate"]["buildDefinition"]["externalParameters"]["model"] == "m"
    assert stmt["predicate"]["doctrine"] == "evidence not conformity"

    ok, why = attest.verify_statement(
        stmt, expected_digest=dg, predicate_type="https://example.test/pred/v1"
    )
    assert ok and why == "ok", (ok, why)


def test_verify_rejects_wrong_digest_and_type():
    dg = _digest({"seq": 2})
    stmt = attest.build_statement(
        subject_name="r", subject_digest=dg, predicate={}, predicate_type="p/v1"
    )
    # Wrong subject digest -> not bound.
    ok, why = attest.verify_statement(stmt, expected_digest="deadbeef")
    assert ok is False and why == "subject-digest-not-bound", (ok, why)
    # Wrong predicate type -> rejected.
    ok2, why2 = attest.verify_statement(
        stmt, expected_digest=dg, predicate_type="other/v1"
    )
    assert ok2 is False and why2 == "unexpected-predicate-type", (ok2, why2)
    # A non-statement never raises.
    ok3, _ = attest.verify_statement({"nope": 1}, expected_digest=dg)
    assert ok3 is False


def test_compliance_energy_measured_vs_unmeasured():
    caps_measured = {"logging": True, "integrity": True, "governance": True, "energy": True}
    caps_unmeasured = dict(caps_measured, energy=False)

    ev_m = attest.compliance_evidence(capabilities=caps_measured, subject_digest="d")
    by_id_m = {c["id"]: c for c in ev_m["controls"]}
    assert by_id_m["NIST-AI-RMF-MEASURE-2.x"]["status"] == "supports"
    assert ev_m["measured_energy"] is True

    ev_u = attest.compliance_evidence(capabilities=caps_unmeasured)
    by_id_u = {c["id"]: c for c in ev_u["controls"]}
    # Energy-dependent control honestly degrades; logging still supported.
    assert by_id_u["NIST-AI-RMF-MEASURE-2.x"]["status"] == "UNAVAILABLE"
    assert by_id_u["EU-AI-Act-Art-12"]["status"] == "supports"
    assert by_id_u["EU-AI-Act-Art-19"]["status"] == "supports"


def test_compliance_is_evidence_not_conformity():
    ev = attest.compliance_evidence(
        capabilities={"logging": True, "integrity": True, "governance": True}
    )
    for c in ev["controls"]:
        assert c["does_not_establish"], c
    assert "not a conformity assessment" in ev["disclaimer"].lower()
    art15 = next(c for c in ev["controls"] if c["id"] == "EU-AI-Act-Art-15")
    assert "does not establish model accuracy" in art15["does_not_establish"].lower()


def test_absent_capability_is_unavailable_not_supports():
    # A receipt with NO governance capability must not silently "support" GOVERN.
    ev = attest.compliance_evidence(capabilities={"logging": True})
    by_id = {c["id"]: c for c in ev["controls"]}
    assert by_id["NIST-AI-RMF-GOVERN-1.x"]["status"] == "UNAVAILABLE"
    assert by_id["EU-AI-Act-Art-15"]["status"] == "UNAVAILABLE"


def test_statement_is_canonical_json_serializable():
    dg = _digest({"seq": 3})
    stmt = attest.build_statement(subject_name="r", subject_digest=dg, predicate={"a": 1})
    reparsed = json.loads(attest.to_json(stmt))
    assert reparsed == stmt


if __name__ == "__main__":
    test_build_statement_and_verify_binding()
    test_verify_rejects_wrong_digest_and_type()
    test_compliance_energy_measured_vs_unmeasured()
    test_compliance_is_evidence_not_conformity()
    test_absent_capability_is_unavailable_not_supports()
    test_statement_is_canonical_json_serializable()
    print("ok: all shared attest tests passed")
