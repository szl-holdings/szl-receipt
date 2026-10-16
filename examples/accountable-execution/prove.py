"""Proof harness for the accountable-execution guarantee.

Runs six properties, each with the adversary/negative control that would break a
naive implementation, and an independent verifier that reconciles signed receipts
against the real external world. Exit 0 iff every property and invariant holds.

    python3 -I prove.py
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gexec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
_PLAIN = os.environ.get("NO_COLOR") is not None or not sys.stdout.isatty()
PASS = "PASS" if _PLAIN else "\033[32mPASS\033[0m"
FAIL = "FAIL" if _PLAIN else "\033[31mFAIL\033[0m"
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  [{PASS if ok else FAIL}] {name}" + (f"  — {detail}" if detail else ""))
    return ok


def fresh():
    d = tempfile.mkdtemp(prefix="gexec_", dir=HERE)
    return d, os.path.join(d, "authority.db"), os.path.join(d, "world.db")


def keys():
    return Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()


def new_grant(auth, action, *, attempt=None, nonce=None, ttl=30.0, now=None, allowance=None):
    attempt = attempt or "att-" + secrets.token_hex(6)
    nonce = nonce or "n-" + secrets.token_hex(6)
    env = auth.issue(proposal_id="p-" + secrets.token_hex(4), action=action,
                     target="svc://pay/charge",
                     allowance_id=allowance or "al-" + secrets.token_hex(4),
                     attempt_id=attempt, nonce=nonce, ttl_s=ttl, now=now)
    return env, attempt


# ------------------------------------------------------------------ property 1
def property_1_adversarial_grants_zero_effects():
    print("\nProperty 1 — wrong-digest / expired / replayed grants cause ZERO new effects")
    d, lp, wp = fresh()
    ap, ep = keys()
    auth = gexec.Authorizer(ap, "policy-v1")
    led, world = gexec.AuthorityLedger(lp), gexec.ExternalWorld(wp)
    ex = gexec.GovernedExecutor(led, world, auth.pub, ep)

    # wrong-digest: grant for action A, execute a tampered action B
    action_a = {"op": "charge", "amount": 100, "to": "acct-1"}
    env, att = new_grant(auth, action_a)
    led.register(env)
    tampered = {"op": "charge", "amount": 9999, "to": "acct-attacker"}
    out = ex.execute(tampered, env)
    check("wrong-digest rejected", out.status == "REJECTED" and out.reason == "action-digest-mismatch", out.reason)
    check("wrong-digest produced 0 effects", world.count(att) == 0)

    # expired: grant already past its TTL
    env2, att2 = new_grant(auth, action_a, ttl=-5.0)
    led.register(env2)
    out2 = ex.execute(action_a, env2)
    check("expired rejected", out2.status == "REJECTED" and out2.reason == "grant-expired", out2.reason)
    check("expired produced 0 effects", world.count(att2) == 0)

    # replay: a fully valid grant used twice -> second use is a no-op
    env3, att3 = new_grant(auth, action_a)
    led.register(env3)
    first = ex.execute(action_a, env3)
    second = ex.execute(action_a, env3)
    check("first use commits", first.status == "COMMITTED")
    check("replayed use rejected", second.status == "REJECTED", second.reason)
    check("replay produced no SECOND effect (exactly 1 total)", world.count(att3) == 1)

    shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------------ property 2
def property_2_concurrency_at_most_one():
    print("\nProperty 2 — concurrent attempts produce AT MOST ONE effect")
    d, lp, wp = fresh()
    ap, ep = keys()
    auth = gexec.Authorizer(ap, "policy-v1")
    led, world = gexec.AuthorityLedger(lp), gexec.ExternalWorld(wp)
    ex = gexec.GovernedExecutor(led, world, auth.pub, ep)

    action = {"op": "charge", "amount": 250, "to": "acct-7"}
    env, att = new_grant(auth, action)
    led.register(env)

    N = 24
    outs, barrier = [None] * N, threading.Barrier(N)

    def run(i):
        barrier.wait()  # maximize contention
        outs[i] = ex.execute(action, env)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(N)]
    for t in threads: t.start()
    for t in threads: t.join()

    commits = sum(1 for o in outs if o and o.status == "COMMITTED")
    check(f"{N} concurrent same-grant/same-nonce attempts (replay contention) -> exactly 1 commit",
          commits == 1, f"commits={commits}")
    check("exactly 1 external effect", world.count(att) == 1, f"effects={world.count(att)}")

    # second layer, independently: bypass the claim, hammer the external world's
    # idempotency key directly from N threads -> still at most one effect.
    d2, _, wp2 = fresh()
    w2 = gexec.ExternalWorld(wp2)
    created = [False] * N
    b2 = threading.Barrier(N)

    def hammer(i):
        b2.wait()
        c, _ = w2.apply("same-key", "att-x", "svc://pay", gexec.canon(action))
        created[i] = c

    t2 = [threading.Thread(target=hammer, args=(i,)) for i in range(N)]
    for t in t2: t.start()
    for t in t2: t.join()
    check("external idempotency layer: exactly 1 effect under N writers",
          sum(created) == 1 and w2.count() == 1, f"created={sum(created)} effects={w2.count()}")

    shutil.rmtree(d, ignore_errors=True)
    shutil.rmtree(d2, ignore_errors=True)


# ------------------------------------------------------------------ property 3
def _run_crash(lp, wp, apub_hex, epriv_hex, action, grant_env, point):
    job = {"ledger": lp, "world": wp, "authorizer_pub": apub_hex, "exec_priv": epriv_hex,
           "action": action, "grant_env": grant_env, "crash_point": point}
    jp = os.path.join(os.path.dirname(lp), "job.json")
    with open(jp, "w") as f:
        json.dump(job, f)
    r = subprocess.run([sys.executable, os.path.join(HERE, "crash_worker.py"), jp],
                       cwd=HERE, capture_output=True, text=True)
    return r.returncode


def property_3_crash_never_false_success():
    print("\nProperty 3 — crash before/after dispatch never silently becomes success")
    ap, ep = keys()
    auth = gexec.Authorizer(ap, "policy-v1")
    apub_hex = ap.public_key().public_bytes_raw().hex()
    epriv_hex = ep.private_bytes_raw().hex()
    action = {"op": "charge", "amount": 500, "to": "acct-9"}

    for point, expect_effect, expect_verdict in [
        ("after_claim", 0, gexec.KNOWN_NOT_DISPATCHED),
        ("after_dispatch_authorized", 0, gexec.KNOWN_NOT_DISPATCHED),
        ("after_effect_before_receipt", 1, gexec.COMMITTED),
    ]:
        d, lp, wp = fresh()
        led, _world = gexec.AuthorityLedger(lp), gexec.ExternalWorld(wp)
        env, att = new_grant(auth, action)
        led.register(env)

        rc = _run_crash(lp, wp, apub_hex, epriv_hex, action, env, point)
        crashed = rc == 42
        # no receipt was written by the crashed worker
        pre_receipts = led.all_receipts()

        # RESTART: a fresh executor against the same durable stores runs recovery.
        ex2 = gexec.GovernedExecutor(gexec.AuthorityLedger(lp), gexec.ExternalWorld(wp),
                                     auth.pub, ep)
        resolved = dict(ex2.recover())
        verdict = resolved.get(att)
        effects = gexec.ExternalWorld(wp).count(att)

        check(f"[{point}] worker hard-crashed", crashed, f"rc={rc}")
        check(f"[{point}] no success receipt before recovery", len(pre_receipts) == 0)
        check(f"[{point}] effect count = {expect_effect}", effects == expect_effect, f"effects={effects}")
        check(f"[{point}] recovery verdict = {expect_verdict}", verdict == expect_verdict, f"verdict={verdict}")
        # the decisive one: a committed verdict exists ONLY when a real effect exists
        committed_without_effect = (verdict == gexec.COMMITTED and effects == 0)
        check(f"[{point}] no success claim without a real effect", not committed_without_effect)
        # recovery must not create a second effect (idempotency holds across restart)
        ex2.recover()
        check(f"[{point}] re-running recovery creates no extra effect",
              gexec.ExternalWorld(wp).count(att) == effects)
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------------ property 4
def property_4_independent_verifier():
    print("\nProperty 4 — an independent verifier reconciles receipts with external state")
    d, lp, wp = fresh()
    ap, ep = keys()
    auth = gexec.Authorizer(ap, "policy-v1")
    led, world = gexec.AuthorityLedger(lp), gexec.ExternalWorld(wp)
    ex = gexec.GovernedExecutor(led, world, auth.pub, ep)

    # a realistic mixed estate: some commits, a rejected adversary, a replay
    for i in range(5):
        a = {"op": "charge", "amount": 10 * (i + 1), "to": f"acct-{i}"}
        env, _ = new_grant(auth, a)
        led.register(env)
        ex.execute(a, env)
    # adversary: wrong-digest (must leave no effect, no committed receipt)
    aenv, aatt = new_grant(auth, {"op": "charge", "amount": 1, "to": "x"})
    led.register(aenv)
    ex.execute({"op": "charge", "amount": 999, "to": "attacker"}, aenv)

    inv = gexec.independent_verify(led, world, auth.pub, ep.public_key())
    for i in inv:
        check(f"invariant: {i.name}", i.ok, i.detail)

    # NEGATIVE CONTROLS — the verifier must DETECT tampering (not rubber-stamp):
    # (a) forge an external effect with no authority
    world.apply("forged-key", "att-forged", "svc://pay", b"{}")
    inv_a = {i.name: i.ok for i in gexec.independent_verify(led, world, auth.pub, ep.public_key())}
    check("detects a forged effect with no authority",
          not inv_a["no_effect_without_committed_authority"])

    # (b) tamper a stored receipt's bytes -> signature must fail verification
    d2, lp2, wp2 = fresh()
    led2, world2 = gexec.AuthorityLedger(lp2), gexec.ExternalWorld(wp2)
    ex2 = gexec.GovernedExecutor(led2, world2, auth.pub, ep)
    a = {"op": "charge", "amount": 42, "to": "acct-z"}
    env, att = new_grant(auth, a)
    led2.register(env); ex2.execute(a, env)
    c = led2._conn()
    row = c.execute("SELECT envelope FROM receipts WHERE attempt_id=?", (att,)).fetchone()
    tampered_env = json.loads(row["envelope"])
    p = json.loads(tampered_env["payload"]); p["amount_stolen"] = True
    tampered_env["payload"] = gexec.canon(p).decode()
    c.execute("UPDATE receipts SET envelope=? WHERE attempt_id=?", (json.dumps(tampered_env), att))
    c.commit(); c.close()
    inv_b = {i.name: i.ok for i in gexec.independent_verify(led2, world2, auth.pub, ep.public_key())}
    check("detects a tampered receipt (signature breaks)",
          not inv_b["every_committed_receipt_backed_by_effect"])

    shutil.rmtree(d, ignore_errors=True)
    shutil.rmtree(d2, ignore_errors=True)


# ------------------------------------------------------------------ property 5
def property_5_composition_integrity():
    print("\nProperty 5 — action snapshot, effect-identity reconciliation, atomic nonce+claim")
    ap, ep = keys()
    auth = gexec.Authorizer(ap, "policy-v1")

    # 5a: action mutated AFTER the authority check -> the SNAPSHOT is dispatched (TOCTOU)
    d, lp, wp = fresh()
    led, world = gexec.AuthorityLedger(lp), gexec.ExternalWorld(wp)
    ex = gexec.GovernedExecutor(led, world, auth.pub, ep)
    a = {"op": "charge", "amount": 100, "to": "acct-1"}
    env, att = new_grant(auth, a); led.register(env)
    live = dict(a)
    out = ex.execute(live, env, crash_hook=lambda p: (
        live.__setitem__("amount", 9999) if p == "after_dispatch_authorized" else None))
    authorized = json.loads(env["payload"])["action_digest"]
    check("action mutated post-validation -> snapshot dispatched (TOCTOU closed)",
          out.status == "COMMITTED" and live["amount"] == 9999
          and world.get(att)["payload_sha256"] == authorized)

    # 5b: existing key with a different target/payload -> NEVER COMMITTED
    d2, lp2, wp2 = fresh()
    led2, world2 = gexec.AuthorityLedger(lp2), gexec.ExternalWorld(wp2)
    ex2 = gexec.GovernedExecutor(led2, world2, auth.pub, ep)
    b = {"op": "charge", "amount": 250, "to": "acct-7"}
    env2, _ = new_grant(auth, b, attempt="att-conf"); led2.register(env2)
    world2.apply("att-conf", "att-conf", "svc://evil", gexec.canon({"op": "steal"}))
    o2 = ex2.execute(b, env2)
    check("existing key, different content -> idempotency-key-conflict, not COMMITTED",
          o2.status == "REJECTED" and o2.reason == "idempotency-key-conflict"
          and led2.row("att-conf")["verdict"] == gexec.EFFECT_CONFLICT)

    # 5c: crash right after the atomic nonce+claim -> CLAIMED & recoverable, never stranded
    d3, lp3, wp3 = fresh()
    led3 = gexec.AuthorityLedger(lp3); gexec.ExternalWorld(wp3)
    cc = {"op": "charge", "amount": 500, "to": "acct-9"}
    env3, att3 = new_grant(auth, cc); led3.register(env3)
    job = {"ledger": lp3, "world": wp3, "authorizer_pub": ap.public_key().public_bytes_raw().hex(),
           "exec_priv": ep.private_bytes_raw().hex(), "action": cc, "grant_env": env3,
           "crash_point": "after_claim"}
    with open(os.path.join(d3, "job.json"), "w") as f:
        json.dump(job, f)
    rc = subprocess.run([sys.executable, os.path.join(HERE, "crash_worker.py"),
                         os.path.join(d3, "job.json")], cwd=HERE, capture_output=True, text=True).returncode
    # read the post-crash state and invariant BEFORE recovery (recover() finalises it)
    state_after_crash = gexec.AuthorityLedger(lp3).row(att3)["state"]
    inv = {i.name: i.ok for i in gexec.independent_verify(
        gexec.AuthorityLedger(lp3), gexec.ExternalWorld(wp3), auth.pub, ep.public_key())}
    verdict = dict(gexec.GovernedExecutor(gexec.AuthorityLedger(lp3), gexec.ExternalWorld(wp3),
                                          auth.pub, ep).recover()).get(att3)
    check("crash after atomic nonce+claim -> CLAIMED, not stranded, recoverable",
          rc == 42 and state_after_crash == gexec.CLAIMED
          and inv["no_consumed_nonce_with_available_attempt"]
          and verdict == gexec.KNOWN_NOT_DISPATCHED)

    # 5d: the real effect's content is altered after commit -> the verifier detects it
    d4, lp4, wp4 = fresh()
    led4, world4 = gexec.AuthorityLedger(lp4), gexec.ExternalWorld(wp4)
    ex4 = gexec.GovernedExecutor(led4, world4, auth.pub, ep)
    e = {"op": "charge", "amount": 42, "to": "acct-z"}
    env4, att4 = new_grant(auth, e); led4.register(env4); ex4.execute(e, env4)
    c4 = world4._conn()
    c4.execute("UPDATE effects SET payload_sha256=? WHERE idempotency_key=?", ("00" * 32, att4))
    c4.commit(); c4.close()
    inv4 = {i.name: i.ok for i in gexec.independent_verify(led4, world4, auth.pub, ep.public_key())}
    check("detects effect-content tamper after commit",
          not inv4["every_committed_receipt_backed_by_effect"])

    for x in (d, d2, d3, d4):
        shutil.rmtree(x, ignore_errors=True)


# ------------------------------------------------------------------ property 6
def property_6_grant_binding_and_recovery_fencing():
    print("\nProperty 6 — verified-grant snapshot, claim CAS, recovery fencing, receipt semantics")
    ap, ep = keys()
    auth = gexec.Authorizer(ap, "policy-v1")

    def fresh_stack():
        d, lp, wp = fresh()
        led, world = gexec.AuthorityLedger(lp), gexec.ExternalWorld(wp)
        return d, led, world, gexec.GovernedExecutor(led, world, auth.pub, ep)

    def receipts_consistent(led, world):
        return {i.name: i.ok for i in gexec.independent_verify(
            led, world, auth.pub, ep.public_key())}["every_receipt_consistent_with_ledger_and_grant"]

    a = {"op": "charge", "amount": 77, "to": "acct-6"}
    dirs = []

    # 6a: an envelope whose payload changes between reads cannot redirect dispatch
    d, led, world, ex = fresh_stack(); dirs.append(d)
    env, att = new_grant(auth, a); led.register(env)
    injected = json.loads(env["payload"]); injected["target"] = "svc://evil"

    class Shifting(dict):
        reads = 0

        def __getitem__(self, key):
            if key == "payload":
                Shifting.reads += 1
                if Shifting.reads > 1:
                    return gexec.canon(injected).decode()
            return super().__getitem__(key)

    out = ex.execute(a, Shifting(env))
    check("grant payload changed after verification -> only the signed target dispatched",
          out.status == "COMMITTED" and world.get(att)["target"] == "svc://pay/charge",
          f"dispatched={world.get(att)['target']}")

    # 6b: the claim CAS raced DIRECTLY (dispatch lock bypassed): distinct signed nonces,
    #     one attempt, every contender carrying the registered identity, so only the
    #     compare-and-swap itself can serialise them.
    d, led, world, ex = fresh_stack(); dirs.append(d)
    env, att = new_grant(auth, a, allowance="al-shared"); led.register(env)
    contenders = [env] + [new_grant(auth, a, attempt=att, allowance="al-shared")[0]
                          for _ in range(15)]
    checks = [gexec.verify_grant(e, auth.pub, a) for e in contenders]
    results = [None] * len(checks)
    barrier = threading.Barrier(len(checks))

    def claim(i):
        barrier.wait()
        results[i] = led.consume_nonce_and_claim(
            checks[i].grant.nonce, att, grant=checks[i].grant, grant_env=checks[i].envelope)
    ts = [threading.Thread(target=claim, args=(i,)) for i in range(len(checks))]
    for t in ts: t.start()
    for t in ts: t.join()
    check("claim CAS raced directly by 16 distinct signed nonces -> exactly 1 winner",
          all(c.ok for c in checks) and results.count("ok") == 1
          and results.count("not-claimable") == 15,
          f"ok={results.count('ok')} not_claimable={results.count('not-claimable')}")

    # 6c: recovery overlapping a live dispatch whose provider commits but loses the response
    d, led, world, ex = fresh_stack(); dirs.append(d)
    env, att = new_grant(auth, a); led.register(env)
    paused, resume, res = threading.Event(), threading.Event(), {}

    def hold(point):
        if point == "after_dispatch_authorized":
            paused.set(); resume.wait(10)
    w = threading.Thread(target=lambda: res.setdefault("o", ex.execute(
        a, env, crash_hook=hold, provider_fault="lose_response_after_commit")))
    w.start(); paused.wait(10)
    rec = gexec.GovernedExecutor(gexec.AuthorityLedger(led.path), gexec.ExternalWorld(world.path), auth.pub, ep)
    during = dict(rec.recover()).get(att)
    resume.set(); w.join(10)
    after = dict(rec.recover()).get(att)
    check("recovery overlapping a live dispatch + lost response -> skipped, then COMMITTED",
          during is None and after == gexec.COMMITTED and world.count(att) == 1,
          f"during={during} after={after} effects={world.count(att)}")

    # 6d: an out-of-band close after claim fences the dispatch
    env, att = new_grant(auth, a); led.register(env)
    out = ex.execute(a, env, crash_hook=lambda p: (
        led.finalize(att, gexec.CLOSED, gexec.KNOWN_NOT_DISPATCHED) if p == "after_claim" else None))
    check("attempt closed out of band after claim -> dispatch fenced, 0 effects",
          out.reason == "fenced-before-dispatch" and world.count(att) == 0, out.reason)

    # 6e: receipt and effect agree with each other but not with the signed grant
    d, led, world, ex = fresh_stack(); dirs.append(d)
    env, att = new_grant(auth, a); led.register(env)
    claimed = json.loads(env["payload"]); claimed["target"] = "svc://other"
    world.apply(att, att, "svc://other", gexec.canon(a))
    led.record_receipt(att, ex._receipt(claimed, world.get(att)["effect_id"], gexec.COMMITTED))
    led.finalize(att, gexec.CLOSED, gexec.COMMITTED)
    check("detects a receipt that disagrees with the signed grant", not receipts_consistent(led, world))

    # 6f: validly signed non-COMMITTED receipt contradicting a committed ledger/effect
    d, led, world, ex = fresh_stack(); dirs.append(d)
    env, att = new_grant(auth, a); led.register(env); ex.execute(a, env)
    c = led._conn(); c.execute("DELETE FROM receipts WHERE attempt_id=?", (att,)); c.commit(); c.close()
    led.record_receipt(att, ex._receipt(json.loads(env["payload"]), "none", gexec.KNOWN_NOT_DISPATCHED))
    check("detects a signed non-COMMITTED receipt contradicting the ledger/effect",
          not receipts_consistent(led, world))

    for x in dirs:
        shutil.rmtree(x, ignore_errors=True)


def main():
    t0 = time.time()
    print("=" * 72)
    print("ACCOUNTABLE AI EXECUTION — reference implementation · test suite")
    print("Tested under the explicit assumptions in README.md (threat model).")
    print("=" * 72)
    property_1_adversarial_grants_zero_effects()
    property_2_concurrency_at_most_one()
    property_3_crash_never_false_success()
    property_4_independent_verifier()
    property_5_composition_integrity()
    property_6_grant_binding_and_recovery_fencing()
    ok = sum(results)
    total = len(results)
    print("\n" + "=" * 72)
    print(f"{ok}/{total} checks passed in {time.time()-t0:.2f}s")
    print("ALL CHECKS PASSED — properties hold in this reference implementation,"
          if ok == total else "CHECKS FAILED — see failures above")
    if ok == total:
        print("under the explicit assumptions in README.md. Not a claim about any")
        print("deployed system; see 'What this does and does not establish'.")
    print("=" * 72)
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
