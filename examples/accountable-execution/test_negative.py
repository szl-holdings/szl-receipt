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


if __name__ == "__main__":
    unittest.main(verbosity=2)
