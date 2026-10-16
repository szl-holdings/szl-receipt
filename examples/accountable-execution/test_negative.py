"""Independent negative / adversarial tests for the accountable-execution chain.

Each test asserts that an adversary's attempt is REJECTED or DETECTED — i.e. the
things that MUST NOT happen do not happen. Runs standalone:

    python3 -m unittest test_negative -v

These are deliberately separate from prove.py so the negative controls can be run and
reviewed on their own. They assert behaviour only under the threat model in README.md.
"""
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gexec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="gexec_neg_", dir=HERE)
        self.lp = os.path.join(self.dir, "authority.db")
        self.wp = os.path.join(self.dir, "world.db")
        self.ap = Ed25519PrivateKey.generate()
        self.ep = Ed25519PrivateKey.generate()
        self.auth = gexec.Authorizer(self.ap, "policy-v1")
        self.led = gexec.AuthorityLedger(self.lp)
        self.world = gexec.ExternalWorld(self.wp)
        self.ex = gexec.GovernedExecutor(self.led, self.world, self.auth.pub, self.ep)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def grant(self, action, **kw):
        att = kw.pop("attempt", "att-" + secrets.token_hex(6))
        env = self.auth.issue(proposal_id="p", action=action, target="svc://pay",
                              allowance_id="al", attempt_id=att,
                              nonce="n-" + secrets.token_hex(6), **kw)
        self.led.register(env)
        return env, att


class TestAuthorityExactAndSingleUse(Base):
    def test_wrong_digest_is_rejected_with_zero_effects(self):
        env, att = self.grant({"op": "charge", "amount": 100})
        out = self.ex.execute({"op": "charge", "amount": 9999}, env)   # tampered
        self.assertEqual(out.status, "REJECTED")
        self.assertEqual(out.reason, "action-digest-mismatch")
        self.assertEqual(self.world.count(att), 0)

    def test_expired_grant_is_rejected_with_zero_effects(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action, ttl_s=-5.0)
        out = self.ex.execute(action, env)
        self.assertEqual(out.status, "REJECTED")
        self.assertEqual(out.reason, "grant-expired")
        self.assertEqual(self.world.count(att), 0)

    def test_forged_grant_signature_is_rejected(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        env["signatures"][0]["sig"] = ("00" * 64)   # forged signature
        out = self.ex.execute(action, env)
        self.assertEqual(out.status, "REJECTED")
        self.assertEqual(out.reason, "grant-signature-invalid")
        self.assertEqual(self.world.count(att), 0)

    def test_replay_produces_no_second_effect(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        self.assertEqual(self.ex.execute(action, env).status, "COMMITTED")
        self.assertEqual(self.ex.execute(action, env).status, "REJECTED")
        self.assertEqual(self.world.count(att), 1)


class TestConcurrency(Base):
    def test_concurrent_attempts_produce_at_most_one_effect(self):
        """Same grant and same nonce from every contender: replay/claim contention.
        TestDistinctNonceContention isolates the claim CAS with distinct nonces."""
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        N = 24
        outs = [None] * N
        barrier = threading.Barrier(N)

        def run(i):
            barrier.wait()
            outs[i] = self.ex.execute(action, env)

        ts = [threading.Thread(target=run, args=(i,)) for i in range(N)]
        for t in ts: t.start()
        for t in ts: t.join()
        self.assertEqual(sum(1 for o in outs if o.status == "COMMITTED"), 1)
        self.assertEqual(self.world.count(att), 1)


class TestIndependentVerifierDetectsTampering(Base):
    def test_forged_effect_without_authority_is_detected(self):
        self.world.apply("forged-key", "att-forged", "svc://pay", b"{}")
        inv = {i.name: i.ok for i in gexec.independent_verify(
            self.led, self.world, self.auth.pub, self.ep.public_key())}
        self.assertFalse(inv["no_effect_without_committed_authority"])

    def test_tampered_receipt_is_detected(self):
        action = {"op": "charge", "amount": 42}
        env, att = self.grant(action)
        self.ex.execute(action, env)
        c = self.led._conn()
        row = c.execute("SELECT envelope FROM receipts WHERE attempt_id=?", (att,)).fetchone()
        env2 = json.loads(row["envelope"])
        p = json.loads(env2["payload"]); p["amount_stolen"] = True
        env2["payload"] = gexec.canon(p).decode()
        c.execute("UPDATE receipts SET envelope=? WHERE attempt_id=?", (json.dumps(env2), att))
        c.commit(); c.close()
        inv = {i.name: i.ok for i in gexec.independent_verify(
            self.led, self.world, self.auth.pub, self.ep.public_key())}
        self.assertFalse(inv["every_committed_receipt_backed_by_effect"])


class TestCrashNeverFakesSuccess(Base):
    def _crash(self, action, env, point):
        job = {"ledger": self.lp, "world": self.wp,
               "authorizer_pub": self.ap.public_key().public_bytes_raw().hex(),
               "exec_priv": self.ep.private_bytes_raw().hex(),
               "action": action, "grant_env": env, "crash_point": point}
        jp = os.path.join(self.dir, "job.json")
        with open(jp, "w") as f:
            json.dump(job, f)
        return subprocess.run([sys.executable, os.path.join(HERE, "crash_worker.py"), jp],
                              cwd=HERE, capture_output=True, text=True).returncode

    def test_crash_before_effect_is_not_committed(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        rc = self._crash(action, env, "after_dispatch_authorized")
        self.assertEqual(rc, 42)                       # real hard crash
        self.assertEqual(self.led.all_receipts(), [])  # no success receipt
        ex2 = gexec.GovernedExecutor(gexec.AuthorityLedger(self.lp),
                                     gexec.ExternalWorld(self.wp), self.auth.pub, self.ep)
        verdict = dict(ex2.recover()).get(att)
        self.assertEqual(verdict, gexec.KNOWN_NOT_DISPATCHED)
        self.assertEqual(gexec.ExternalWorld(self.wp).count(att), 0)

    def test_crash_after_effect_commits_exactly_once(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        rc = self._crash(action, env, "after_effect_before_receipt")
        self.assertEqual(rc, 42)
        self.assertEqual(self.led.all_receipts(), [])  # effect happened, receipt not yet written
        ex2 = gexec.GovernedExecutor(gexec.AuthorityLedger(self.lp),
                                     gexec.ExternalWorld(self.wp), self.auth.pub, self.ep)
        verdict = dict(ex2.recover()).get(att)
        self.assertEqual(verdict, gexec.COMMITTED)      # reconciled via external readback
        self.assertEqual(gexec.ExternalWorld(self.wp).count(att), 1)
        ex2.recover()                                   # idempotent recovery
        self.assertEqual(gexec.ExternalWorld(self.wp).count(att), 1)


class TestActionSnapshot(Base):
    def test_action_mutation_after_validation_dispatches_the_snapshot(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        live = dict(action)
        out = self.ex.execute(live, env, crash_hook=lambda p: (
            live.__setitem__("amount", 9999) if p == "after_dispatch_authorized" else None))
        self.assertEqual(out.status, "COMMITTED")
        self.assertEqual(live["amount"], 9999)                 # the mutation really happened
        authorized = json.loads(env["payload"])["action_digest"]
        self.assertEqual(self.world.get(att)["payload_sha256"], authorized)  # snapshot dispatched


class TestEffectIdentityReconciliation(Base):
    def test_existing_key_with_different_content_is_not_committed(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        self.world.apply(att, att, "svc://evil", gexec.canon({"op": "steal"}))  # foreign effect first
        out = self.ex.execute(action, env)
        self.assertEqual(out.status, "REJECTED")
        self.assertEqual(out.reason, "idempotency-key-conflict")
        self.assertEqual(self.led.row(att)["verdict"], gexec.EFFECT_CONFLICT)

    def test_tampered_effect_content_is_detected_by_verifier(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        self.ex.execute(action, env)
        c = self.world._conn()
        c.execute("UPDATE effects SET payload_sha256=? WHERE idempotency_key=?", ("00" * 32, att))
        c.commit(); c.close()
        inv = {i.name: i.ok for i in gexec.independent_verify(
            self.led, self.world, self.auth.pub, self.ep.public_key())}
        self.assertFalse(inv["every_committed_receipt_backed_by_effect"])


class TestAtomicNonceClaim(Base):
    def test_crash_after_claim_never_strands_an_available_attempt(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        job = {"ledger": self.lp, "world": self.wp,
               "authorizer_pub": self.ap.public_key().public_bytes_raw().hex(),
               "exec_priv": self.ep.private_bytes_raw().hex(),
               "action": action, "grant_env": env, "crash_point": "after_claim"}
        jp = os.path.join(self.dir, "job.json")
        with open(jp, "w") as f:
            json.dump(job, f)
        rc = subprocess.run([sys.executable, os.path.join(HERE, "crash_worker.py"), jp],
                            cwd=HERE, capture_output=True, text=True).returncode
        self.assertEqual(rc, 42)
        self.assertEqual(self.led.row(att)["state"], gexec.CLAIMED)   # claimed, not AVAILABLE
        inv = {i.name: i.ok for i in gexec.independent_verify(
            self.led, self.world, self.auth.pub, self.ep.public_key())}
        self.assertTrue(inv["no_consumed_nonce_with_available_attempt"])
        ex2 = gexec.GovernedExecutor(gexec.AuthorityLedger(self.lp),
                                     gexec.ExternalWorld(self.wp), self.auth.pub, self.ep)
        self.assertEqual(dict(ex2.recover()).get(att), gexec.KNOWN_NOT_DISPATCHED)


def _issue(auth, action, attempt, *, target="svc://pay", nonce=None):
    return auth.issue(proposal_id="p", action=action, target=target, allowance_id="al",
                      attempt_id=attempt, nonce=nonce or "n-" + secrets.token_hex(6))


class TestVerifiedGrantSnapshot(Base):
    def test_envelope_changing_between_reads_cannot_redirect_dispatch(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        injected = json.loads(env["payload"])
        injected["target"] = "svc://evil"

        class Shifting(dict):
            reads = 0

            def __getitem__(self, key):
                if key == "payload":
                    Shifting.reads += 1
                    if Shifting.reads > 1:
                        return gexec.canon(injected).decode()
                return super().__getitem__(key)

        out = self.ex.execute(action, Shifting(env))
        self.assertEqual(out.status, "COMMITTED")
        self.assertEqual(self.world.get(att)["target"], "svc://pay")   # the signed target only
        inv = {i.name: i.ok for i in gexec.independent_verify(
            self.led, self.world, self.auth.pub, self.ep.public_key())}
        self.assertTrue(all(inv.values()), inv)

    def test_grant_identity_must_match_registered_authority(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)                                  # registered: svc://pay
        other = _issue(self.auth, action, att, target="svc://other")   # validly signed, same attempt
        out = self.ex.execute(action, other)
        self.assertEqual((out.status, out.reason), ("REJECTED", "grant-authority-mismatch"))
        self.assertEqual(self.world.count(att), 0)


class TestReceiptSemantics(Base):
    def _inv(self):
        return {i.name: i.ok for i in gexec.independent_verify(
            self.led, self.world, self.auth.pub, self.ep.public_key())}

    def test_signed_grant_and_receipt_target_disagreement_is_detected(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        claimed = json.loads(env["payload"])
        claimed["target"] = "svc://other"                  # receipt and effect agree with each other
        self.world.apply(att, att, "svc://other", gexec.canon(action))
        self.led.record_receipt(att, self.ex._receipt(claimed, self.world.get(att)["effect_id"],
                                                      gexec.COMMITTED))
        self.led.finalize(att, gexec.CLOSED, gexec.COMMITTED)
        self.assertFalse(self._inv()["every_receipt_consistent_with_ledger_and_grant"])

    def test_signed_non_committed_receipt_mismatch_is_detected(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        self.ex.execute(action, env)                       # ledger COMMITTED, one real effect
        c = self.led._conn()
        c.execute("DELETE FROM receipts WHERE attempt_id=?", (att,))
        c.commit(); c.close()
        self.led.record_receipt(att, self.ex._receipt(json.loads(env["payload"]), "none",
                                                      gexec.KNOWN_NOT_DISPATCHED))
        self.assertFalse(self._inv()["every_receipt_consistent_with_ledger_and_grant"])

    def test_receipt_identity_swap_is_detected(self):
        action = {"op": "charge", "amount": 100}
        env_x, att_x = self.grant(action)
        env_y, att_y = self.grant(action)
        self.ex.execute(action, env_x)
        self.ex.execute(action, env_y)
        receipt_x = [r for r in self.led.all_receipts() if r["attempt_id"] == att_x][0]["envelope"]
        c = self.led._conn()
        c.execute("UPDATE receipts SET envelope=? WHERE attempt_id=?", (receipt_x, att_y))
        c.commit(); c.close()
        self.assertFalse(self._inv()["every_receipt_consistent_with_ledger_and_grant"])


class TestExecutionRecoveryFencing(Base):
    def _overlap(self, pause_point, **execute_kw):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        paused, resume = threading.Event(), threading.Event()

        def hook(point):
            if point == pause_point:
                paused.set()
                resume.wait(10)

        result = {}
        worker = threading.Thread(target=lambda: result.setdefault(
            "out", self.ex.execute(action, env, crash_hook=hook, **execute_kw)))
        worker.start()
        self.assertTrue(paused.wait(10))
        recoverer = gexec.GovernedExecutor(gexec.AuthorityLedger(self.lp),
                                           gexec.ExternalWorld(self.wp), self.auth.pub, self.ep)
        during = dict(recoverer.recover()).get(att)
        resume.set()
        worker.join(10)
        return att, during, result["out"], recoverer

    def test_recovery_overlapping_live_dispatch_does_not_lose_a_committed_effect(self):
        # recovery runs while dispatch is in flight; the provider then commits but loses
        # its response. The effect must still end COMMITTED, never KNOWN_NOT_DISPATCHED.
        att, during, out, recoverer = self._overlap(
            "after_dispatch_authorized", provider_fault="lose_response_after_commit")
        self.assertIsNone(during)                          # live attempt skipped, not guessed
        self.assertEqual(out.status, "UNKNOWN")
        self.assertEqual(dict(recoverer.recover()).get(att), gexec.COMMITTED)
        self.assertEqual(self.led.row(att)["verdict"], gexec.COMMITTED)
        self.assertEqual(self.world.count(att), 1)

    def test_recovery_overlapping_live_claim_is_skipped(self):
        att, during, out, _ = self._overlap("after_claim")
        self.assertIsNone(during)
        self.assertEqual(out.status, "COMMITTED")
        self.assertEqual(self.world.count(att), 1)

    def test_out_of_band_close_after_claim_fences_dispatch(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)

        def close_out_of_band(point):
            if point == "after_claim":
                self.led.finalize(att, gexec.CLOSED, gexec.KNOWN_NOT_DISPATCHED)

        out = self.ex.execute(action, env, crash_hook=close_out_of_band)
        self.assertEqual((out.status, out.reason), ("REJECTED", "fenced-before-dispatch"))
        self.assertEqual(self.world.count(att), 0)


class TestDistinctNonceContention(Base):
    """Isolates the claim compare-and-swap: every contender holds a distinct, validly
    signed nonce for the SAME attempt, so nonce de-duplication cannot be what
    serialises them (kept separate from same-grant/same-nonce replay contention)."""

    def test_distinct_signed_nonces_sharing_one_attempt_claim_exactly_once(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        grants = [env] + [_issue(self.auth, action, att) for _ in range(15)]
        self.assertEqual(len({json.loads(g["payload"])["nonce"] for g in grants}), 16)
        outs = [None] * len(grants)
        barrier = threading.Barrier(len(grants))

        def run(i):
            barrier.wait()
            outs[i] = self.ex.execute(action, grants[i])

        threads = [threading.Thread(target=run, args=(i,)) for i in range(len(grants))]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(sum(o.status == "COMMITTED" for o in outs), 1)
        self.assertTrue(all(o.reason == "not-available-or-already-claimed"
                            for o in outs if o.status != "COMMITTED"))
        self.assertEqual(self.world.count(att), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
