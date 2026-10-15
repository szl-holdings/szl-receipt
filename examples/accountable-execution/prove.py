"""Proof harness for the accountable-execution guarantee.

Runs four properties, each with the adversary/negative control that would break a
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


def new_grant(auth, action, *, attempt=None, nonce=None, ttl=30.0, now=None):
    attempt = attempt or "att-" + secrets.token_hex(6)
    nonce = nonce or "n-" + secrets.token_hex(6)
    env = auth.issue(proposal_id="p-" + secrets.token_hex(4), action=action,
                     target="svc://pay/charge", allowance_id="al-" + secrets.token_hex(4),
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
    check(f"{N} concurrent attempts -> exactly 1 commit", commits == 1, f"commits={commits}")
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
        led, world = gexec.AuthorityLedger(lp), gexec.ExternalWorld(wp)
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
