"""Falsifiable acceptance matrix (A–F) for accountable execution.

Each row is an adversary or scenario from the assignment's matrix. The suite runs
it, asserts the required behaviour, and emits a machine-readable DEMO_CASES row
(id, category, description, label, evidence). It is a reference implementation
under the README threat model — NOT a claim about any deployed system.

    python3 acceptance_matrix.py            # run + print the matrix
    python3 acceptance_matrix.py --json      # also write DEMO_CASES.json

'Zero effects' is asserted with an authoritative counter query against the external
world (world.count), never by silence. Crashes use a real subprocess hard-exit.
"""
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gexec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
ROWS = []
_ALL_OK = True


def record(cid, category, desc, ok, evidence):
    global _ALL_OK
    _ALL_OK = _ALL_OK and ok
    ROWS.append({"id": cid, "category": category, "description": desc,
                 "label": "PASS" if ok else "FAIL", "evidence": evidence})


def env():
    d = tempfile.mkdtemp(prefix="gexec_m_", dir=HERE)
    ap, ep = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    auth = gexec.Authorizer(ap, "policy-v1")
    led = gexec.AuthorityLedger(os.path.join(d, "authority.db"))
    world = gexec.ExternalWorld(os.path.join(d, "world.db"))
    ex = gexec.GovernedExecutor(led, world, auth.pub, ep)
    return d, ap, ep, auth, led, world, ex


def grant(auth, led, action, *, register=True, tenant="tenant-A", ttl=30.0, attempt=None):
    att = attempt or "att-" + secrets.token_hex(6)
    g = auth.issue(proposal_id="p", action=action, target="svc://pay", allowance_id="al",
                   attempt_id=att, nonce="n-" + secrets.token_hex(6), tenant=tenant, ttl_s=ttl)
    if register:
        led.register(g)
    return g, att


def run_crash(d, lp, wp, ap, ep, action, g, point):
    job = {"ledger": lp, "world": wp, "authorizer_pub": ap.public_key().public_bytes_raw().hex(),
           "exec_priv": ep.private_bytes_raw().hex(), "action": action, "grant_env": g,
           "crash_point": point}
    jp = os.path.join(d, "job.json")
    with open(jp, "w") as f:
        json.dump(job, f)
    return subprocess.run([sys.executable, os.path.join(HERE, "crash_worker.py"), jp],
                          cwd=HERE, capture_output=True, text=True).returncode


# ----------------------------------------------------------------- A: authority
def cat_A():
    d, ap, ep, auth, led, world, ex = env()
    action = {"op": "charge", "amount": 100, "to": "acct-1"}

    g, att = grant(auth, led, action)
    o = ex.execute({"op": "charge", "amount": 9999, "to": "x"}, g)  # tampered body
    record("A1", "authority", "tampered body / wrong digest -> deny, 0 effects",
           o.status == "REJECTED" and o.reason == "action-digest-mismatch" and world.count(att) == 0,
           f"{o.reason}; effects={world.count(att)}")

    g, att = grant(auth, led, action, ttl=-5.0)
    o = ex.execute(action, g)
    record("A2", "authority", "expired grant -> deny, 0 effects",
           o.status == "REJECTED" and o.reason == "grant-expired" and world.count(att) == 0,
           f"{o.reason}; effects={world.count(att)}")

    g, att = grant(auth, led, action, register=False)  # never registered
    o = ex.execute(action, g)
    record("A3", "authority", "missing authority (unregistered attempt) -> deny, 0 effects",
           o.status == "REJECTED" and world.count(att) == 0,
           f"{o.reason}; effects={world.count(att)}")

    g, att = grant(auth, led, action, tenant="tenant-A")
    o = ex.execute(action, g, expected_tenant="tenant-B")  # wrong tenant at the boundary
    record("A4", "authority", "wrong tenant -> deny, 0 effects",
           o.status == "REJECTED" and o.reason == "wrong-tenant" and world.count(att) == 0,
           f"{o.reason}; effects={world.count(att)}")

    g, att = grant(auth, led, action)
    first, second = ex.execute(action, g), ex.execute(action, g)  # replay
    record("A5", "authority", "replayed/consumed grant -> second denied, exactly 1 effect",
           first.status == "COMMITTED" and second.status == "REJECTED" and world.count(att) == 1,
           f"first={first.status} second={second.reason}; effects={world.count(att)}")

    g, att = grant(auth, led, action)
    g["signatures"][0]["sig"] = "00" * 64  # forged signature
    o = ex.execute(action, g)
    record("A6", "authority", "forged grant signature -> deny, 0 effects",
           o.status == "REJECTED" and o.reason == "grant-signature-invalid" and world.count(att) == 0,
           f"{o.reason}; effects={world.count(att)}")

    # A7: snapshot — mutating the caller's action AFTER the authority check must not
    #     change the authorized or dispatched bytes (time-of-check/time-of-use closed).
    g7, att7 = grant(auth, led, action)
    live = dict(action)
    o = ex.execute(live, g7, crash_hook=lambda p: (
        live.__setitem__("amount", 9999) if p == "after_dispatch_authorized" else None))
    eff = world.get(att7)
    authorized = json.loads(g7["payload"])["action_digest"]
    snap_ok = (o.status == "COMMITTED" and eff is not None
               and eff["payload_sha256"] == authorized and live["amount"] == 9999)
    record("A7", "authority", "action mutated after validation -> snapshot dispatched, not the mutation",
           snap_ok, f"status={o.status} effect==authorized={eff is not None and eff['payload_sha256']==authorized} mutated={live['amount']==9999}")
    shutil.rmtree(d, ignore_errors=True)


# ----------------------------------------------------------------- B: at-most-once
def cat_B():
    d, ap, ep, auth, led, world, ex = env()
    action = {"op": "charge", "amount": 250, "to": "acct-7"}
    g, att = grant(auth, led, action)
    N = 24
    outs = [None] * N
    b = threading.Barrier(N)

    def run(i):
        b.wait()
        outs[i] = ex.execute(action, g)
    ts = [threading.Thread(target=run, args=(i,)) for i in range(N)]
    for t in ts: t.start()
    for t in ts: t.join()
    commits = sum(1 for o in outs if o.status == "COMMITTED")
    losers_truthful = all(o.status == "REJECTED" for o in outs if o.status != "COMMITTED")
    record("B1", "at-most-once", "N concurrent identical requests -> exactly 1 effect; losers truthful",
           commits == 1 and world.count(att) == 1 and losers_truthful,
           f"commits={commits} effects={world.count(att)} losers_truthful={losers_truthful}")

    # different payloads, same idempotency key -> still at most one effect
    d2, *_ , world2, _ = env()
    c1, _ = world2.apply("same-key", "att-x", "svc://pay", gexec.canon({"amount": 1}))
    c2, _ = world2.apply("same-key", "att-x", "svc://pay", gexec.canon({"amount": 999}))
    record("B2", "at-most-once", "different payloads, same idempotency key -> exactly 1 effect",
           c1 is True and c2 is False and world2.count() == 1,
           f"created=({c1},{c2}) effects={world2.count()}")

    # B3: an effect already present under this key with a DIFFERENT target/payload must
    #     NEVER be reported COMMITTED — effect-identity reconciliation against the grant.
    d3, ap3, ep3, auth3, led3, world3, ex3 = env()
    actx = {"op": "charge", "amount": 250, "to": "acct-7"}
    g3, att3 = grant(auth3, led3, actx, attempt="att-conflict")
    world3.apply("att-conflict", "att-conflict", "svc://evil", gexec.canon({"op": "steal"}))  # foreign pre-effect
    o3 = ex3.execute(actx, g3)
    v3 = gexec.AuthorityLedger(led3.path).row("att-conflict")["verdict"]
    record("B3", "at-most-once", "existing key, different target/payload -> not COMMITTED (conflict)",
           o3.status == "REJECTED" and o3.reason == "idempotency-key-conflict" and v3 == gexec.EFFECT_CONFLICT,
           f"status={o3.status} reason={o3.reason} verdict={v3}")
    shutil.rmtree(d, ignore_errors=True)
    shutil.rmtree(d2, ignore_errors=True)
    shutil.rmtree(d3, ignore_errors=True)


# ----------------------------------------------------------------- C: crashes
def cat_C():
    auth_priv, exec_priv = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    auth = gexec.Authorizer(auth_priv, "policy-v1")
    action = {"op": "charge", "amount": 500, "to": "acct-9"}
    plan = [
        ("C1", "after_claim", gexec.KNOWN_NOT_DISPATCHED, 0),
        ("C2", "after_dispatch_authorized", gexec.KNOWN_NOT_DISPATCHED, 0),
        ("C3", "after_effect_before_receipt", gexec.COMMITTED, 1),
        ("C4", "after_close_before_return", None, 1),  # already CLOSED; recovery is a no-op
    ]
    for cid, point, verdict, effects in plan:
        d = tempfile.mkdtemp(prefix="gexec_m_", dir=HERE)
        lp, wp = os.path.join(d, "authority.db"), os.path.join(d, "world.db")
        led = gexec.AuthorityLedger(lp)
        gexec.ExternalWorld(wp)
        g, att = grant(auth, led, action)
        rc = run_crash(d, lp, wp, auth_priv, exec_priv, action, g, point)
        pre_receipts = led.all_receipts()
        ex2 = gexec.GovernedExecutor(gexec.AuthorityLedger(lp), gexec.ExternalWorld(wp),
                                     auth.pub, exec_priv)
        resolved = dict(ex2.recover())
        cnt = gexec.ExternalWorld(wp).count(att)
        ex2.recover()  # idempotent
        cnt2 = gexec.ExternalWorld(wp).count(att)
        if point == "after_close_before_return":
            row = gexec.AuthorityLedger(lp).row(att)
            ok = (rc == 42 and cnt == 1 and cnt2 == 1 and len(pre_receipts) == 1
                  and row["state"] == gexec.CLOSED)
            ev = f"crashed={rc==42} closed={row['state']} effects={cnt} receipts(pre)={len(pre_receipts)}"
        else:
            v = resolved.get(att)
            no_false_success = not (v == gexec.COMMITTED and cnt == 0)
            ok = (rc == 42 and len(pre_receipts) == 0 and cnt == effects
                  and v == verdict and no_false_success and cnt2 == cnt)
            ev = f"crashed={rc==42} verdict={v} effects={cnt} no_false_success={no_false_success}"
        desc = f"hard crash @ {point} -> never a false success; resolved by external readback"
        record(cid, "crash", desc, ok, ev)
        shutil.rmtree(d, ignore_errors=True)

    # C5: atomic nonce+claim. A hard crash right after the combined claim leaves a
    #     CLAIMED, recoverable attempt — NEVER an AVAILABLE attempt with a burned
    #     nonce (the stranded-forever state dot reported is now unreachable).
    d = tempfile.mkdtemp(prefix="gexec_m_", dir=HERE)
    lp, wp = os.path.join(d, "authority.db"), os.path.join(d, "world.db")
    led = gexec.AuthorityLedger(lp); gexec.ExternalWorld(wp)
    g, att = grant(auth, led, action)
    rc = run_crash(d, lp, wp, auth_priv, exec_priv, action, g, "after_claim")
    row = gexec.AuthorityLedger(lp).row(att)
    inv = {i.name: i.ok for i in gexec.independent_verify(
        gexec.AuthorityLedger(lp), gexec.ExternalWorld(wp), auth.pub, exec_priv.public_key())}
    ex2 = gexec.GovernedExecutor(gexec.AuthorityLedger(lp), gexec.ExternalWorld(wp), auth.pub, exec_priv)
    verdict = dict(ex2.recover()).get(att)
    ok = (rc == 42 and row["state"] == gexec.CLAIMED
          and inv["no_consumed_nonce_with_available_attempt"]
          and verdict == gexec.KNOWN_NOT_DISPATCHED)
    record("C5", "crash", "crash after atomic nonce+claim -> CLAIMED & recoverable, never stranded AVAILABLE",
           ok, f"crashed={rc==42} state={row['state']} no_stranded={inv['no_consumed_nonce_with_available_attempt']} verdict={verdict}")
    shutil.rmtree(d, ignore_errors=True)


# ----------------------------------------------------------------- D: provider faults
def cat_D():
    d, ap, ep, auth, led, world, ex = env()
    action = {"op": "charge", "amount": 70, "to": "acct-d"}

    g, att = grant(auth, led, action)
    o = ex.execute(action, g, provider_fault="fail_before_commit")
    ex.recover()
    verdict = gexec.AuthorityLedger(led.path).row(att)["verdict"]
    record("D1", "provider-fault", "provider fails before commit -> UNKNOWN; recovery -> not dispatched, 0 effects",
           o.status == "UNKNOWN" and world.count(att) == 0 and verdict == gexec.KNOWN_NOT_DISPATCHED,
           f"{o.reason}; effects={world.count(att)}; verdict={verdict}")

    g, att = grant(auth, led, action)
    o = ex.execute(action, g, provider_fault="lose_response_after_commit")
    # the effect committed but the response was lost; a timeout is NOT proof of no-effect.
    ex.recover()
    verdict = gexec.AuthorityLedger(led.path).row(att)["verdict"]
    record("D2", "provider-fault", "provider commits but response lost -> UNKNOWN; recovery confirms by readback, 1 effect",
           o.status == "UNKNOWN" and world.count(att) == 1 and verdict == gexec.COMMITTED,
           f"{o.reason}; effects={world.count(att)}; verdict={verdict}")
    shutil.rmtree(d, ignore_errors=True)


# ----------------------------------------------------------------- E: tamper / lying executor
def cat_E():
    d, ap, ep, auth, led, world, ex = env()
    action = {"op": "charge", "amount": 42, "to": "acct-e"}

    # happy run to populate a valid estate, then mutate each layer independently
    g, att = grant(auth, led, action)
    ex.execute(action, g)

    world.apply("forged-key", "att-forged", "svc://pay", b"{}")  # forged effect, no authority
    inv = {i.name: i.ok for i in gexec.independent_verify(led, world, auth.pub, ep.public_key())}
    record("E1", "tamper", "forged external effect with no authority -> verifier detects",
           not inv["no_effect_without_committed_authority"], "verifier flagged unauthorized effect")

    # tamper a stored receipt's bytes -> signature breaks
    d2, ap2, ep2, auth2, led2, world2, ex2 = env()
    g2, att2 = grant(auth2, led2, action)
    ex2.execute(action, g2)
    c = led2._conn()
    row = c.execute("SELECT envelope FROM receipts WHERE attempt_id=?", (att2,)).fetchone()
    e = json.loads(row["envelope"]); p = json.loads(e["payload"]); p["stolen"] = True
    e["payload"] = gexec.canon(p).decode()
    c.execute("UPDATE receipts SET envelope=? WHERE attempt_id=?", (json.dumps(e), att2)); c.commit(); c.close()
    inv2 = {i.name: i.ok for i in gexec.independent_verify(led2, world2, auth2.pub, ep2.public_key())}
    record("E2", "tamper", "tampered receipt bytes -> signature verification fails",
           not inv2["every_committed_receipt_backed_by_effect"], "verifier rejected tampered receipt")

    # lying executor: a signed COMMITTED receipt for an attempt with NO real effect
    d3, ap3, ep3, auth3, led3, world3, ex3 = env()
    g3, att3 = grant(auth3, led3, action)
    lie = ex3._receipt(json.loads(g3["payload"]), "deadbeefdeadbeef", gexec.COMMITTED)
    led3.record_receipt(att3, lie)
    led3.finalize(att3, gexec.CLOSED, gexec.COMMITTED)
    inv3 = {i.name: i.ok for i in gexec.independent_verify(led3, world3, auth3.pub, ep3.public_key())}
    record("E3", "lying-executor", "executor claims COMMITTED but no external effect -> verifier detects",
           not inv3["every_committed_receipt_backed_by_effect"], "verifier rejected a committed receipt with no backing effect")

    # E4: the REAL external effect is altered after a clean commit (its stored content
    #     no longer matches the signed receipt) -> independent verifier detects it.
    d4, ap4, ep4, auth4, led4, world4, ex4 = env()
    g4, att4 = grant(auth4, led4, action)
    ex4.execute(action, g4)                       # clean COMMITTED
    c = world4._conn()
    c.execute("UPDATE effects SET payload_sha256=? WHERE idempotency_key=?", ("00" * 32, att4))
    c.commit(); c.close()
    inv4 = {i.name: i.ok for i in gexec.independent_verify(led4, world4, auth4.pub, ep4.public_key())}
    record("E4", "tamper", "external effect content altered after commit -> verifier detects",
           not inv4["every_committed_receipt_backed_by_effect"], "verifier flagged effect-content mismatch")
    for x in (d, d2, d3, d4):
        shutil.rmtree(x, ignore_errors=True)


# ----------------------------------------------------------------- F: positive path
def cat_F():
    d, ap, ep, auth, led, world, ex = env()
    action = {"op": "charge", "amount": 1234, "to": "acct-f"}
    g, att = grant(auth, led, action)
    o = ex.execute(action, g)
    inv = {i.name: i.ok for i in gexec.independent_verify(led, world, auth.pub, ep.public_key())}
    row = led.row(att)
    ok = (o.status == "COMMITTED" and world.count(att) == 1 and all(inv.values())
          and row["verdict"] == gexec.COMMITTED)
    record("F1", "positive", "authorized path -> exactly one real effect, correct binding, verifier clean",
           ok, f"status={o.status} effects={world.count(att)} invariants_all_ok={all(inv.values())}")
    shutil.rmtree(d, ignore_errors=True)


def main():
    for fn in (cat_A, cat_B, cat_C, cat_D, cat_E, cat_F):
        fn()
    width = max(len(r["description"]) for r in ROWS)
    print("ACCOUNTABLE EXECUTION — falsifiable acceptance matrix (reference implementation)")
    print("Under the explicit assumptions in README.md. Not a claim about a deployed system.\n")
    for r in ROWS:
        print(f"  {r['label']:4}  {r['id']:3} [{r['category']:14}] {r['description']:{width}}  — {r['evidence']}")
    npass = sum(1 for r in ROWS if r["label"] == "PASS")
    print(f"\n{npass}/{len(ROWS)} acceptance rows pass.")
    if "--json" in sys.argv:
        out = os.path.join(HERE, "DEMO_CASES.json")
        with open(out, "w") as f:
            json.dump({"schema": "szl.accountable-execution.demo-cases/1",
                       "note": "Reference implementation under README threat model; not a deployed-system claim.",
                       "rows": ROWS}, f, indent=2)
        print(f"wrote {out}")
    sys.exit(0 if _ALL_OK else 1)


if __name__ == "__main__":
    main()
