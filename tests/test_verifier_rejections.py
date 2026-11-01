# SPDX-License-Identifier: Apache-2.0
"""Malformed public inputs reject; signing fixtures use ephemeral synthetic keys."""
import copy
import json
import sys
import unittest
from unittest.mock import patch

from szl_receipt import (
    Receipt, emit_receipt, generate_keypair, sign_receipt,
    verify_emitted_receipt, verify_pci_receipt,
)
from szl_receipt import sdk
from szl_receipt import lambda_gate
from szl_receipt.pci import emit_pci_receipt
from szl_receipt.sdk import verify_receipt


def unsigned_receipt():
    return emit_receipt(
        model_id="synthetic-model", input_digest="a" * 64,
        output_digest="b" * 64, policy_id="synthetic-policy",
        private_key_pem=None,
    )


def malformed_body_receipt(body):
    return {"envelope": {"payload": "e30=", "signed": False}, "body": body}


class VerifierRejectionTests(unittest.TestCase):
    def assert_rejection(self, receipt, reason, *, signed=False):
        # Both the documented SDK entry point and its package export are public.
        self.assertEqual(verify_receipt(receipt), (False, reason))
        self.assertEqual(verify_emitted_receipt(receipt), (False, reason))
        result = verify_pci_receipt(receipt)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, reason)
        self.assertEqual(result.signed, signed)
        self.assertIsNone(result.advisory)

    def test_json_decoded_lone_surrogate_is_a_stable_rejection(self):
        receipt = json.loads(
            r'{"envelope":{"payload":"e30=","signed":false},"body":{"x":"\ud800"}}'
        )
        before = copy.deepcopy(receipt)
        self.assert_rejection(receipt, "body-canonicalization-error")
        self.assertEqual(receipt, before)

    def test_cyclic_body_is_rejected_without_mutating_the_cycle(self):
        body = {"synthetic": True}
        body["cycle"] = body
        receipt = malformed_body_receipt(body)
        self.assert_rejection(receipt, "body-canonicalization-error")
        self.assertIs(receipt["body"], body)
        self.assertIs(body["cycle"], body)
        self.assertTrue(body["synthetic"])

    def test_nonserializable_body_is_rejected_without_echo_or_mutation(self):
        marker = object()
        for body in ({"unsupported": marker}, {"unsupported": {"synthetic"}},
                     {"unsupported": b"SYNTHETIC_PRIVATE_VALUE"}):
            with self.subTest(type=type(body["unsupported"]).__name__):
                receipt = malformed_body_receipt(body)
                self.assert_rejection(receipt, "body-canonicalization-error")
                self.assertIs(receipt["body"], body)

    def test_recursion_limit_body_is_rejected_without_mutation(self):
        leaf = {"synthetic": True}
        body = leaf
        # Recent CPython encoders also have a C-stack limit that is separate
        # from sys.getrecursionlimit(); exceed both with a small fixed fixture.
        depth = max(10_000, sys.getrecursionlimit() + 32)
        for _ in range(depth):
            body = {"nested": body}
        self.assert_rejection(malformed_body_receipt(body), "body-canonicalization-error")
        cursor = body
        for _ in range(depth):
            cursor = cursor["nested"]
        self.assertIs(cursor, leaf)

    def test_json_nonobject_envelopes_preserve_spine_rejection(self):
        for raw in ('null', 'false', 'true', '0', '1', '1.5', '""', '"x"', '[]', '["x"]'):
            with self.subTest(raw=raw):
                receipt = {"envelope": json.loads(raw)}
                before = copy.deepcopy(receipt)
                self.assert_rejection(receipt, "no-envelope")
                self.assertEqual(receipt, before)

    def test_root_and_empty_envelope_controls_keep_their_reasons(self):
        for value in (None, [], "x", 1, True):
            with self.subTest(value=value):
                self.assert_rejection(value, "not-a-receipt")
        self.assert_rejection({}, "no-envelope")
        for envelope in ({}, {"signed": True}):
            receipt = {"envelope": envelope}
            reason = verify_receipt(receipt)[1]
            self.assertTrue(reason.startswith("envelope-decode-error:"))
            self.assert_rejection(receipt, reason, signed=bool(envelope.get("signed")))

    def test_valid_unsigned_receipt_remains_unsigned_and_unchanged(self):
        receipt = unsigned_receipt()
        before = copy.deepcopy(receipt)
        self.assert_rejection(receipt, "unsigned-honest")
        self.assertEqual(receipt, before)
        self.assertFalse(receipt["envelope"]["signed"])
        self.assertEqual(receipt["envelope"]["signature"], "")

    def test_optional_body_and_existing_binding_reasons_are_preserved(self):
        original = unsigned_receipt()
        for remove in (False, True):
            with self.subTest(remove=remove):
                receipt = copy.deepcopy(original)
                if remove:
                    del receipt["body"]
                else:
                    receipt["body"] = None
                self.assert_rejection(receipt, "unsigned-honest")
        for field, reason in (("body", "body-payload-mismatch"),
                              ("digest", "digest-mismatch"),
                              ("envelope", "envelope-digest-mismatch"),
                              ("statement", "statement-subject-digest-not-bound")):
            with self.subTest(field=field):
                receipt = copy.deepcopy(original)
                if field == "body":
                    receipt["body"]["policy_id"] = "changed-synthetic-policy"
                elif field == "digest":
                    receipt["digest"] = "c" * 64
                elif field == "envelope":
                    receipt["envelope"]["digest"] = "c" * 64
                else:
                    receipt["statement"]["subject"][0]["digest"]["sha256"] = "c" * 64
                before = copy.deepcopy(receipt)
                self.assert_rejection(receipt, reason)
                self.assertEqual(receipt, before)

    def test_non_input_failures_are_not_swallowed_by_canonicalization_guard(self):
        receipt = malformed_body_receipt({})
        for error in (RuntimeError, MemoryError, KeyboardInterrupt):
            with self.subTest(error=error.__name__), patch.object(sdk, "canonical_json", side_effect=error):
                with self.assertRaises(error):
                    verify_receipt(receipt)
                with self.assertRaises(error):
                    verify_pci_receipt(receipt)


class PCIShapeRejectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # In-memory fixture keys only; no key material is written or committed.
        cls.private_key, cls.public_key = generate_keypair()

    def signed_composite(self, body):
        receipt = Receipt(kind="synthetic", body=body)
        return {"body": body, "envelope": sign_receipt(receipt, self.private_key)}

    def valid_pci_body(self):
        return emit_pci_receipt(
            model_id="synthetic", input_digest="a" * 64,
            output_digest="b" * 64, policy_id="synthetic-policy",
            lambda_verdict=lambda_gate.evaluate({"a": 0.9}, {"a": 1.0}, theta=0.8),
        )["body"]

    def test_authenticated_nonobject_and_noniterable_spec_rejects(self):
        for spec in ("x", ["x"], True, 1, 1.5, {"claims": True}, {"invariants": 1}):
            with self.subTest(spec=spec):
                body = self.valid_pci_body()
                body["extra"]["spec"] = spec
                receipt = self.signed_composite(body)
                before = copy.deepcopy(receipt)
                self.assertEqual(verify_receipt(receipt, self.public_key), (True, "ok"))
                result = verify_pci_receipt(receipt, self.public_key)
                self.assertFalse(result.ok)
                self.assertEqual(result.reason, "spec-malformed")
                self.assertTrue(result.signed)
                self.assertEqual(receipt, before)

    def test_authenticated_energy_float_overflow_rejects(self):
        for joules in (10**400, -(10**400)):
            with self.subTest(negative=joules < 0):
                body = self.valid_pci_body()
                body["energy"] = {"joules": joules, "unit": "J"}
                receipt = self.signed_composite(body)
                before = copy.deepcopy(receipt)
                self.assertEqual(verify_receipt(receipt, self.public_key), (True, "ok"))
                result = verify_pci_receipt(receipt, self.public_key)
                self.assertFalse(result.ok)
                self.assertEqual(result.reason, "energy-malformed")
                self.assertEqual(result.energy, "UNAVAILABLE")
                self.assertTrue(result.signed)
                self.assertEqual(receipt, before)

    def test_authenticated_spec_type_confusion_cannot_pass(self):
        cases = (
            ({"claims": {"lambda-advisory": True}}, "spec-malformed"),
            ({"invariants": {"inv1": True}, "locked_count": 1}, "spec-malformed"),
            ({"invariants": [1], "locked_count": 1}, "spec-malformed"),
            ({"invariants": [True], "locked_count": 1}, "spec-malformed"),
            ({"locked_count": False}, "spec-locked-count-mismatch"),
            ({"locked_count": 0.0}, "spec-locked-count-mismatch"),
        )
        for fields, reason in cases:
            with self.subTest(fields=fields):
                body = self.valid_pci_body()
                body["extra"]["spec"].update(fields)
                receipt = self.signed_composite(body)
                self.assertEqual(verify_receipt(receipt, self.public_key), (True, "ok"))
                result = verify_pci_receipt(receipt, self.public_key)
                self.assertFalse(result.ok)
                self.assertEqual(result.reason, reason)
                self.assertTrue(result.signed)

    def test_signed_json_type_matrix_returns_stable_results(self):
        values = (
            None, False, True, 0, 1, -1, 0.5, 10**400, -(10**400),
            "", "x", "locked", [], ["x"], [[]], [{}], {}, {"x": "x"},
            ["lambda-advisory"], {"lambda-advisory": True},
        )
        paths = (
            ("extra", "spec"), ("extra", "spec", "tier"),
            ("extra", "spec", "claims"), ("extra", "spec", "invariants"),
            ("extra", "spec", "locked_count"), ("energy",), ("energy", "joules"),
            ("extra", "attestation"), ("extra", "attestation", "status"),
            ("extra", "lambda_verdict"), ("extra", "lambda_verdict", "scores"),
            ("extra", "lambda_verdict", "weights"),
            ("extra", "lambda_verdict", "scores", "a"),
            ("extra", "lambda_verdict", "weights", "a"),
            ("extra", "lambda_verdict", "lambda"),
            ("extra", "lambda_verdict", "theta"),
            ("extra", "lambda_verdict", "verdict"),
        )
        for path in paths:
            for index, value in enumerate(values):
                with self.subTest(path=".".join(path), value_index=index):
                    body = self.valid_pci_body()
                    body["energy"] = {"joules": 1.0, "unit": "J"}
                    target = body
                    for field in path[:-1]:
                        target = target[field]
                    target[path[-1]] = copy.deepcopy(value)
                    receipt = self.signed_composite(body)
                    before = copy.deepcopy(receipt)
                    self.assertEqual(verify_receipt(receipt, self.public_key), (True, "ok"))
                    result = verify_pci_receipt(receipt, self.public_key)
                    self.assertEqual(result, verify_pci_receipt(receipt, self.public_key))
                    self.assertTrue(result.signed)
                    self.assertIsInstance(result.ok, bool)
                    self.assertIsInstance(result.reason, str)
                    self.assertTrue(result.reason)
                    if result.ok:
                        self.assertIn(result.advisory, ("advisory-pass", "advisory-fail"))
                        self.assertEqual(result.reason, "ok:" + result.advisory)
                    self.assertEqual(receipt, before)
                    receipt["envelope"]["signature"] = "AA=="
                    self.assertEqual(verify_pci_receipt(receipt, self.public_key).reason, "signature mismatch")

    def test_locked_eight_and_advisory_claim_controls(self):
        body = self.valid_pci_body()
        body["extra"]["spec"].update({
            "invariants": ["inv" + str(i) for i in range(8)],
            "locked_count": 8, "tier": "locked",
            "claims": ["lambda-advisory", "lambda-uniqueness-conditional"],
        })
        receipt = self.signed_composite(body)
        result = verify_pci_receipt(receipt, self.public_key)
        self.assertTrue(result.ok)
        self.assertEqual(result.advisory, "advisory-pass")
        body["extra"]["spec"]["claims"] = ["lambda-uniqueness-unconditional"]
        receipt = self.signed_composite(body)
        self.assertEqual(verify_pci_receipt(receipt, self.public_key).reason, "overclaim-conjecture1")

    def test_authenticated_nonobject_body_and_extra_are_profile_rejections(self):
        for raw in ('null', 'false', 'true', '0', '1', '1.5', '""', '"x"', '[]', '["x"]'):
            for field in ("body", "extra"):
                with self.subTest(raw=raw, field=field):
                    value = json.loads(raw)
                    body = value if field == "body" else {"extra": value}
                    receipt = self.signed_composite(body)
                    before = copy.deepcopy(receipt)
                    self.assertEqual(verify_receipt(receipt, self.public_key), (True, "ok"))
                    result = verify_pci_receipt(receipt, self.public_key)
                    self.assertFalse(result.ok)
                    self.assertEqual(result.reason, "not-a-pci-receipt")
                    self.assertTrue(result.signed)
                    self.assertIsNone(result.advisory)
                    self.assertEqual(receipt, before)

    def test_spine_rejection_precedes_profile_shape_rejection(self):
        malformed_bodies = ["x", ["x"], {"extra": "x"}]
        for spec in ("x", {"claims": True}, {"invariants": 1}):
            body = self.valid_pci_body()
            body["extra"]["spec"] = spec
            malformed_bodies.append(body)
        body = self.valid_pci_body()
        body["energy"] = {"joules": 10**400, "unit": "J"}
        malformed_bodies.append(body)
        for index, body in enumerate(malformed_bodies):
            with self.subTest(case=index):
                receipt = self.signed_composite(body)
                # The original valid signature no longer authenticates these bytes.
                receipt["envelope"]["signature"] = "AA=="
                expected = verify_receipt(receipt, self.public_key)
                self.assertEqual(expected, (False, "signature mismatch"))
                result = verify_pci_receipt(receipt, self.public_key)
                self.assertFalse(result.ok)
                self.assertEqual(result.reason, expected[1])
                self.assertTrue(result.signed)

                receipt = self.signed_composite(body)
                expected = verify_receipt(receipt)
                self.assertEqual(expected, (False, "no public key provided"))
                self.assertEqual(verify_pci_receipt(receipt).reason, expected[1])

                receipt["envelope"]["signed"] = False
                self.assertEqual(verify_pci_receipt(receipt).reason, "unsigned-honest")

    def test_valid_signed_pci_verdicts_are_unchanged(self):
        for score, verdict in ((0.9, "advisory-pass"), (0.2, "advisory-fail")):
            with self.subTest(verdict=verdict):
                receipt = emit_pci_receipt(
                    model_id="synthetic", input_digest="a" * 64,
                    output_digest="b" * 64, policy_id="synthetic-policy",
                    lambda_verdict=lambda_gate.evaluate({"a": score}, {"a": 1.0}, theta=0.8),
                    private_key_pem=self.private_key,
                )
                before = copy.deepcopy(receipt)
                result = verify_pci_receipt(receipt, self.public_key)
                self.assertTrue(result.ok)
                self.assertEqual(result.advisory, verdict)
                self.assertTrue(result.signed)
                self.assertEqual(receipt, before)


if __name__ == "__main__":
    unittest.main()
