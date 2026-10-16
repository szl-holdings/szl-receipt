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
import time
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


class TestClaimCasRacedDirectly(Base):
    """The claim CAS raced with the dispatch lock BYPASSED: distinct signed nonces, one
    attempt, the registered identity on every contender. Only the CAS can serialise
    them, so a non-atomic check-then-set lets more than one win."""

    def test_exactly_one_contender_wins_the_raw_claim(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        envs = [env] + [_issue(self.auth, action, att) for _ in range(15)]
        checks = [gexec.verify_grant(e, self.auth.pub, action) for e in envs]
        self.assertTrue(all(c.ok for c in checks))
        results = [None] * len(checks)
        barrier = threading.Barrier(len(checks))

        def claim(i):
            barrier.wait()
            results[i] = self.led.consume_nonce_and_claim(
                checks[i].grant.nonce, att, grant=checks[i].grant, grant_env=checks[i].envelope)

        threads = [threading.Thread(target=claim, args=(i,)) for i in range(len(checks))]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(results.count("ok"), 1, results)
        self.assertEqual(results.count("not-claimable"), len(checks) - 1, results)


class TestClaimBindsTenantAndPolicy(Base):
    def test_other_tenant_cannot_claim(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)                                   # tenant-A registered
        other = self.auth.issue(proposal_id="p", action=action, target="svc://pay",
                                allowance_id="al", attempt_id=att, tenant="tenant-B",
                                nonce="n-" + secrets.token_hex(6))
        out = self.ex.execute(action, other)
        self.assertEqual((out.status, out.reason), ("REJECTED", "grant-authority-mismatch"))
        self.assertEqual(self.world.count(att), 0)

    def test_other_policy_revision_cannot_claim(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)                                   # policy-v1 registered
        other = gexec.Authorizer(self.ap, "policy-v2").issue(
            proposal_id="p", action=action, target="svc://pay", allowance_id="al",
            attempt_id=att, nonce="n-" + secrets.token_hex(6))
        out = self.ex.execute(action, other)
        self.assertEqual((out.status, out.reason), ("REJECTED", "grant-authority-mismatch"))


class TestLockAliasing(Base):
    def _recover_through(self, alias_path):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        paused, resume, out = threading.Event(), threading.Event(), {}

        def hold(point):
            if point == "after_dispatch_authorized":
                paused.set()
                resume.wait(10)

        worker = threading.Thread(target=lambda: out.setdefault("o", self.ex.execute(
            action, env, crash_hook=hold, provider_fault="lose_response_after_commit")))
        worker.start()
        self.assertTrue(paused.wait(10))
        aliased = gexec.GovernedExecutor(gexec.AuthorityLedger(alias_path),
                                         gexec.ExternalWorld(self.wp), self.auth.pub, self.ep)
        during = dict(aliased.recover()).get(att)
        skipped = aliased.last_recovery_skipped
        resume.set()
        worker.join(10)
        after = dict(aliased.recover()).get(att)
        return att, during, skipped, after

    def test_symlinked_ledger_path_shares_the_dispatch_lock(self):
        alias = os.path.join(self.dir, "alias.db")
        os.symlink(self.lp, alias)
        att, during, skipped, after = self._recover_through(alias)
        self.assertIsNone(during)
        self.assertIn((att, "in-flight"), skipped)
        self.assertEqual(after, gexec.COMMITTED)
        self.assertEqual(self.led.row(att)["verdict"], gexec.COMMITTED)

    def test_symlink_from_another_directory_shares_the_dispatch_lock(self):
        other_dir = os.path.join(self.dir, "elsewhere")
        os.makedirs(other_dir)
        alias = os.path.join(other_dir, "authority-alias.db")
        os.symlink(self.lp, alias)
        att, during, skipped, after = self._recover_through(alias)
        self.assertIsNone(during)
        self.assertIn((att, "in-flight"), skipped)
        self.assertEqual(after, gexec.COMMITTED)

    def test_hard_linked_ledger_fails_closed(self):
        # Hard links (same or another directory) cannot be fenced by path, and SQLite
        # does not support them; neither execution nor recovery proceeds through one.
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        other_dir = os.path.join(self.dir, "elsewhere")
        os.makedirs(other_dir)
        alias = os.path.join(other_dir, "authority-hardlink.db")
        os.link(self.lp, alias)
        out = self.ex.execute(action, env)
        self.assertEqual((out.status, out.reason), ("REJECTED", "attempt-lock-unavailable"))
        self.assertEqual(self.world.count(att), 0)
        chk = gexec.verify_grant(env, self.auth.pub, action)
        self.assertEqual(self.led.consume_nonce_and_claim(
            chk.grant.nonce, att, grant=chk.grant, grant_env=chk.envelope), "ok")
        aliased = gexec.GovernedExecutor(gexec.AuthorityLedger(alias),
                                         gexec.ExternalWorld(self.wp), self.auth.pub, self.ep)
        self.assertEqual(aliased.recover(), [])
        self.assertIn((att, "lock-unusable"), aliased.last_recovery_skipped)

    def test_recovery_in_another_process_via_alias_path_is_fenced(self):
        # Same-host, cross-PROCESS: a separate interpreter recovers through a symlinked
        # path while this process holds the attempt mid-dispatch.
        alias = os.path.join(self.dir, "alias.db")
        os.symlink(self.lp, alias)
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        paused, resume, out = threading.Event(), threading.Event(), {}

        def hold(point):
            if point == "after_dispatch_authorized":
                paused.set()
                resume.wait(30)

        worker = threading.Thread(target=lambda: out.setdefault("o", self.ex.execute(
            action, env, crash_hook=hold, provider_fault="lose_response_after_commit")))
        worker.start()
        self.assertTrue(paused.wait(10))
        script = (
            "import json, sys; sys.path.insert(0, sys.argv[1]); import gexec\n"
            "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey\n"
            "ex = gexec.GovernedExecutor(gexec.AuthorityLedger(sys.argv[2]), gexec.ExternalWorld(sys.argv[3]),"
            " Ed25519PublicKey.from_public_bytes(bytes.fromhex(sys.argv[4])),"
            " Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sys.argv[5])))\n"
            "print(json.dumps({'resolved': ex.recover(), 'skipped': ex.last_recovery_skipped}))\n")
        proc = subprocess.run(
            [sys.executable, "-c", script, HERE, alias, self.wp,
             self.ap.public_key().public_bytes_raw().hex(), self.ep.private_bytes_raw().hex()],
            capture_output=True, text=True, timeout=60)
        resume.set()
        worker.join(10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["resolved"], [])
        self.assertIn([att, "in-flight"], report["skipped"])
        self.assertEqual(out["o"].status, "UNKNOWN")
        self.assertEqual(dict(self.ex.recover()).get(att), gexec.COMMITTED)
        self.assertEqual(self.world.count(att), 1)


class TestOutOfBandCloseAfterDispatchAuthorized(Base):
    def test_late_out_of_band_close_never_yields_a_contradictory_receipt(self):
        # A close that races an already-authorised dispatch cannot stop the effect;
        # the executor must then report UNKNOWN, write NO committed receipt, and the
        # independent verifier must surface the contradiction.
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)

        def close_late(point):
            if point == "after_dispatch_authorized":
                self.led.finalize(att, gexec.CLOSED, gexec.KNOWN_NOT_DISPATCHED)

        out = self.ex.execute(action, env, crash_hook=close_late)
        self.assertEqual((out.status, out.reason), ("UNKNOWN", "finalize-fenced"))
        self.assertEqual(self.world.count(att), 1)
        self.assertEqual([r for r in self.led.all_receipts() if r["attempt_id"] == att], [])
        inv = {i.name: i.ok for i in gexec.independent_verify(
            self.led, self.world, self.auth.pub, self.ep.public_key())}
        self.assertFalse(inv["no_effect_for_not_dispatched"])


class TestAdmissionTiming(Base):
    def test_replay_is_rejected_without_waiting_for_an_in_flight_dispatch(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action)
        paused, resume = threading.Event(), threading.Event()

        def hold(point):
            if point == "after_dispatch_authorized":
                paused.set()
                resume.wait(10)

        worker = threading.Thread(target=lambda: self.ex.execute(action, env, crash_hook=hold))
        worker.start()
        self.assertTrue(paused.wait(10))
        t0 = time.monotonic()
        dup = self.ex.execute(action, env)
        waited = time.monotonic() - t0
        resume.set()
        worker.join(10)
        self.assertEqual((dup.status, dup.reason), ("REJECTED", "replay-nonce"))
        self.assertLess(waited, 2.0)
        self.assertEqual(self.world.count(att), 1)

    def test_grant_expiring_while_waiting_for_the_lock_is_rejected(self):
        action = {"op": "charge", "amount": 100}
        env, att = self.grant(action, ttl_s=1.0)
        holder = gexec.GovernedExecutor(gexec.AuthorityLedger(self.lp),
                                        gexec.ExternalWorld(self.wp), self.auth.pub, self.ep)
        held, release = threading.Event(), threading.Event()

        def hold_lock():
            with holder._attempt_lock(att, 5.0) as lock:
                assert lock == "acquired"
                held.set()
                release.wait(10)

        t = threading.Thread(target=hold_lock)
        t.start()
        self.assertTrue(held.wait(10))
        threading.Timer(1.6, release.set).start()
        out = self.ex.execute(action, env)          # verifies fresh, then waits ~1.6 s
        t.join(10)
        self.assertEqual((out.status, out.reason), ("REJECTED", "grant-expired"))
        self.assertEqual(self.world.count(att), 0)


class TestUnusableLockFile(Base):
    def test_unusable_lock_rejects_execute_and_skips_only_that_attempt_in_recovery(self):
        action = {"op": "charge", "amount": 100}
        env_x, att_x = self.grant(action)
        env_y, att_y = self.grant(action)
        for env in (env_x, env_y):
            chk = gexec.verify_grant(env, self.auth.pub, action)
            self.assertEqual(self.led.consume_nonce_and_claim(
                chk.grant.nonce, chk.grant.attempt_id, grant=chk.grant, grant_env=chk.envelope), "ok")
        with open(self.ex._lock_path(att_x), "wb") as f:
            f.write(b"this is not a sqlite database" * 64)
        fresh = self.auth.issue(proposal_id="p", action=action, target="svc://pay",
                                allowance_id="al", attempt_id=att_x, nonce="n-" + secrets.token_hex(6))
        out = self.ex.execute(action, fresh)
        self.assertEqual((out.status, out.reason), ("REJECTED", "attempt-lock-unavailable"))
        resolved = dict(self.ex.recover())
        self.assertEqual(resolved.get(att_y), gexec.KNOWN_NOT_DISPATCHED)   # pass not aborted
        self.assertIn((att_x, "lock-unusable"), self.ex.last_recovery_skipped)


class TestMalformedEnvelopes(Base):
    def test_malformed_envelopes_are_rejected_not_raised(self):
        action = {"op": "charge", "amount": 100}
        for env in ({"signatures": ["x"]},
                    {"payloadType": gexec.GRANT_TYPE, "payload": 1, "signatures": ["x"]},
                    {"payloadType": gexec.GRANT_TYPE, "payload": "{}", "signatures": [{}]},
                    ["not", "a", "mapping"]):
            out = self.ex.execute(action, env)
            self.assertEqual(out.status, "REJECTED", env)


class TestReviewRegressions(Base):
    def invariants(self):
        return {i.name: i for i in gexec.independent_verify(
            self.led, self.world, self.auth.pub, self.ep.public_key())}

    def test_old_caller_timestamp_cannot_revive_expired_grant(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action, now=time.time() - 100, ttl_s=1)
        old = json.loads(env["payload"])["issued_at"]
        self.assertEqual(self.ex.execute(action, env, now=old).status, "REJECTED")
        self.assertEqual(self.world.count(att), 0)

    def test_future_dated_grant_is_not_yet_valid(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action, now=time.time() + 100)
        self.assertEqual(self.ex.execute(action, env).status, "REJECTED")
        self.assertEqual(self.world.count(att), 0)

    def test_expiry_during_claim_prevents_dispatch(self):
        from unittest.mock import patch
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action)
        expiry = json.loads(env["payload"])["expires_at"]
        real_claim = self.led.consume_nonce_and_claim
        clock = [time.time()]
        def claim(*args, **kwargs):
            status = real_claim(*args, **kwargs)
            clock[0] = expiry + 1
            return status
        with patch.object(self.led, "consume_nonce_and_claim", claim):
            with patch.object(gexec.time, "time", lambda: clock[0]):
                out = self.ex.execute(action, env)
        self.assertEqual(out.status, "REJECTED")
        self.assertEqual(self.world.count(att), 0)

    def test_effect_must_use_authorized_idempotency_key(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action)
        grant = json.loads(env["payload"])
        _, effect = self.world.apply("foreign-key", att, grant["target"], gexec.canon(action))
        self.led.record_receipt(att, self.ex._receipt(grant, effect, gexec.COMMITTED))
        self.led.finalize(att, gexec.CLOSED, gexec.COMMITTED)
        inv = self.invariants()
        self.assertIs(inv["at_most_one_effect_per_attempt"].ok, False)
        self.assertIs(inv["every_committed_receipt_backed_by_effect"].ok, False)

    def test_expired_effect_without_dispatch_authorization_is_detected(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action, ttl_s=-1)
        grant = json.loads(env["payload"])
        _, effect = self.world.apply(att, att, grant["target"], gexec.canon(action))
        self.led.record_receipt(att, self.ex._receipt(grant, effect, gexec.COMMITTED))
        self.led.finalize(att, gexec.CLOSED, gexec.COMMITTED)
        self.assertIs(self.invariants()["no_effect_without_committed_authority"].ok, False)

    def test_late_dispatch_timestamp_is_detected(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action)
        self.assertEqual(self.ex.execute(action, env).status, "COMMITTED")
        c = self.led._conn()
        c.execute("UPDATE authority SET dispatched_at=? WHERE attempt_id=?",
                  (json.loads(env["payload"])["expires_at"] + 1, att))
        c.commit(); c.close()
        self.assertIs(self.invariants()["no_effect_without_committed_authority"].ok, False)

    def test_malformed_stored_receipts_are_reported_not_raised(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action)
        self.ex.execute(action, env)
        for raw in ("not json", "[]", "null", "42"):
            with self.subTest(raw=raw):
                c = self.led._conn()
                c.execute("UPDATE receipts SET envelope=? WHERE attempt_id=?", (raw, att))
                c.commit(); c.close()
                self.assertIs(self.invariants()["every_committed_receipt_backed_by_effect"].ok, False)

    def test_malformed_stored_grants_are_reported_not_raised(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action)
        for raw in ("not json", "[]", "null", "42"):
            with self.subTest(raw=raw):
                c = self.led._conn()
                c.execute("UPDATE authority SET grant_env=? WHERE attempt_id=?", (raw, att))
                c.commit(); c.close()
                self.assertIs(self.invariants()["all_grants_authorizer_signed"].ok, False)

    def test_deeply_nested_stored_receipt_is_reported_not_raised(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action)
        self.assertEqual(self.ex.execute(action, env).status, "COMMITTED")
        raw = "[" * 10000 + "0" + "]" * 10000
        c = self.led._conn()
        try:
            c.execute("UPDATE receipts SET envelope=? WHERE attempt_id=?", (raw, att))
            c.commit()
        finally:
            c.close()
        self.assertIs(self.invariants()["every_committed_receipt_backed_by_effect"].ok, False)

    def test_deeply_nested_stored_grant_is_reported_not_raised(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action)
        self.assertEqual(self.ex.execute(action, env).status, "COMMITTED")
        raw = "[" * 10000 + "0" + "]" * 10000
        c = self.led._conn()
        try:
            c.execute("UPDATE authority SET grant_env=? WHERE attempt_id=?", (raw, att))
            c.commit()
        finally:
            c.close()
        self.assertIs(self.invariants()["all_grants_authorizer_signed"].ok, False)

    def test_deeply_nested_request_payload_is_rejected(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action)
        env["payload"] = "[" * 10000 + "0" + "]" * 10000
        self.assertEqual(self.ex.execute(action, env).status, "REJECTED")
        self.assertEqual(self.world.count(att), 0)

    def test_deeply_nested_signature_structure_is_rejected(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action)
        nested = None
        for _ in range(10000):
            nested = [nested]
        env["signatures"] = nested
        self.assertEqual(self.ex.execute(action, env).status, "REJECTED")
        self.assertEqual(self.world.count(att), 0)

    def test_stale_receipt_prevents_atomic_close(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action)
        old = self.ex._receipt(json.loads(env["payload"]), "", gexec.KNOWN_NOT_DISPATCHED)
        self.led.record_receipt(att, old)
        out = self.ex.execute(action, env)
        self.assertEqual(out.status, "UNKNOWN")
        row = self.led.row(att)
        self.assertEqual(row["state"], gexec.DISPATCH_AUTHORIZED)
        self.assertIsNone(row["verdict"])
        self.assertEqual(json.loads(self.led.all_receipts()[0]["envelope"]), old)

    def test_signed_tenant_substitution_is_detected(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action)
        self.ex.execute(action, env)
        grant = json.loads(env["payload"])
        grant["tenant"] = "tenant-B"
        alternate = gexec.sign_envelope(grant, self.ap, gexec.GRANT_TYPE)
        c = self.led._conn()
        c.execute("UPDATE authority SET grant_env=? WHERE attempt_id=?", (json.dumps(alternate), att))
        c.commit(); c.close()
        inv = self.invariants()
        self.assertIs(inv["grant_identity_bound_to_ledger"].ok, False)
        self.assertIs(inv["every_receipt_consistent_with_ledger_and_grant"].ok, False)

    def test_verification_during_live_effect_is_unresolved_not_tamper(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action)
        observed = []
        def inspect(point):
            if point == "after_effect_before_receipt":
                observed.extend(self.invariants().values())
        self.assertEqual(self.ex.execute(action, env, crash_hook=inspect).status, "COMMITTED")
        self.assertTrue(observed)
        self.assertFalse(any(i.ok is False for i in observed), observed)
        self.assertTrue(any(i.ok is None for i in observed), observed)
        self.assertTrue(all(i.ok is True for i in self.invariants().values()))


    def test_verifier_retries_a_commit_during_external_snapshot(self):
        from unittest.mock import patch
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action)
        real_all = self.world.all
        calls = []
        def read():
            rows = real_all()
            if not calls:
                calls.append(True)
                self.assertEqual(self.ex.execute(action, env).status, "COMMITTED")
            return rows
        with patch.object(self.world, "all", read):
            self.assertTrue(all(i.ok is True for i in self.invariants().values()))

    def test_verifier_reports_continuous_ledger_changes_as_unresolved(self):
        from unittest.mock import patch
        counter = [0]
        def changing():
            counter[0] += 1
            return ([{"version": counter[0]}], [], [])
        with patch.object(self.led, "verification_snapshot", changing):
            inv = self.invariants()
        self.assertIs(inv["verification_snapshot_stable"].ok, None)

    def test_signed_non_mapping_payload_is_rejected(self):
        for payload in ([], 42, "text"):
            with self.subTest(payload=payload):
                env = gexec.sign_envelope(payload, self.ap, gexec.GRANT_TYPE)
                self.assertIsNone(gexec.verify_envelope(env, self.auth.pub, gexec.GRANT_TYPE))


    def test_signed_malformed_grants_fail_closed_without_exceptions(self):
        action = {"op": "charge", "amount": 1}
        env, att = self.grant(action)
        original = json.loads(env["payload"])
        cases = [(field, value) for field in ("proposal_id", "target", "tenant",
                 "policy_revision", "allowance_id", "attempt_id", "nonce")
                 for value in ([], "", 42)]
        cases += [("action_digest", "invalid"), ("expires_at", 10**1000),
                  ("issued_at", float("nan")), ("expires_at", float("inf")),
                  ("issued_at", True)]
        for field, value in cases:
            with self.subTest(field=field, value=repr(value)[:50]):
                payload = dict(original, **{field: value})
                malformed = gexec.sign_envelope(payload, self.ap, gexec.GRANT_TYPE)
                self.assertEqual(self.ex.execute(action, malformed).status, "REJECTED")
                self.assertEqual(self.world.count(att), 0)
                c = self.led._conn()
                c.execute("UPDATE authority SET grant_env=? WHERE attempt_id=?",
                          (json.dumps(malformed), att))
                c.commit(); c.close()
                self.assertIs(self.invariants()["all_grants_authorizer_signed"].ok, False)


if __name__ == "__main__":
    unittest.main(verbosity=2)

