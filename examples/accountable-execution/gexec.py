"""Accountable AI execution — a durable, idempotent governed executor.

Threat model and guarantee: see README.md. In one sentence: an agent proposes an
action, a trusted policy signs a grant bound to the EXACT request, an executor
independently re-checks that authority, performs the effect against a SEPARATE
durable external world under an idempotency key, and an independent verifier
reconciles signed receipts against the actual external state. No charge, no
network — two local SQLite stores model the governance ledger and the external
world as distinct durable systems (you cannot two-phase-commit with a real
external API, so this uses the real pattern: durable intent -> idempotent
external call -> reconcile by readback).

Python stdlib + `cryptography` only.
"""
from __future__ import annotations

import json
import hashlib
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------- canonical + crypto
def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def action_digest(action: dict) -> str:
    return sha256_hex(canon(action))


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode()
    return b" ".join([b"DSSEv1", str(len(t)).encode(), t, str(len(payload)).encode(), payload])


def key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes_raw()
    return sha256_hex(raw)[:16]


ENVELOPE_TYPE = "application/vnd.szl.gexec.receipt+json"
GRANT_TYPE = "application/vnd.szl.gexec.grant+json"


def sign_envelope(payload: dict, priv: Ed25519PrivateKey, payload_type: str) -> dict:
    body = canon(payload)
    sig = priv.sign(dsse_pae(payload_type, body))
    return {
        "payloadType": payload_type,
        "payload": body.decode(),
        "signatures": [{"keyid": key_id(priv.public_key()), "sig": sig.hex()}],
    }


def verify_envelope(env: dict, trusted_pub: Ed25519PublicKey, payload_type: str) -> Optional[dict]:
    """Return the payload dict iff the envelope is well-formed and the signature
    verifies over the canonical bytes under the trusted key; else None."""
    try:
        if env.get("payloadType") != payload_type:
            return None
        body = env["payload"].encode()
        if json.loads(body) is None:
            return None
        # bind the signed bytes to the canonical form (no body-swap under a valid sig)
        if canon(json.loads(body)) != body:
            return None
        sig_entry = env["signatures"][0]
        if sig_entry.get("keyid") != key_id(trusted_pub):
            return None
        trusted_pub.verify(bytes.fromhex(sig_entry["sig"]), dsse_pae(payload_type, body))
        return json.loads(body)
    except (InvalidSignature, KeyError, ValueError, IndexError, TypeError):
        return None


# ---------------------------------------------------------------- grant
@dataclass(frozen=True)
class Grant:
    proposal_id: str
    action_digest: str
    target: str
    tenant: str
    policy_revision: str
    allowance_id: str
    attempt_id: str      # single-use authorized attempt; also the idempotency key
    nonce: str
    issued_at: float
    expires_at: float

    def body(self) -> dict:
        return asdict(self)


class Authorizer:
    """Trusted policy. Signs a grant bound to the exact action."""

    def __init__(self, priv: Ed25519PrivateKey, policy_revision: str):
        self._priv = priv
        self.policy_revision = policy_revision

    @property
    def pub(self) -> Ed25519PublicKey:
        return self._priv.public_key()

    def issue(self, *, proposal_id, action: dict, target, allowance_id, attempt_id,
              nonce, tenant: str = "tenant-A", ttl_s: float = 30.0,
              now: Optional[float] = None) -> dict:
        now = time.time() if now is None else now
        g = Grant(
            proposal_id=proposal_id,
            action_digest=action_digest(action),
            target=target,
            tenant=tenant,
            policy_revision=self.policy_revision,
            allowance_id=allowance_id,
            attempt_id=attempt_id,
            nonce=nonce,
            issued_at=now,
            expires_at=now + ttl_s,
        )
        return sign_envelope(g.body(), self._priv, GRANT_TYPE)


@dataclass
class Check:
    ok: bool
    reason: str = "ok"
    grant: Optional[Grant] = None      # immutable snapshot of the VERIFIED grant
    envelope: Optional[dict] = None    # the exact envelope snapshot that was verified


def snapshot_envelope(env) -> Optional[dict]:
    """Read every field of a caller-owned envelope exactly once and return a plain,
    JSON-round-tripped copy. Verification and every later use read only this copy,
    so a mapping that changes between reads (or a caller that mutates it
    concurrently) cannot substitute a target or identity after verification."""
    try:
        snap = {"payloadType": env.get("payloadType"), "payload": env["payload"],
                "signatures": env["signatures"]}
        return json.loads(json.dumps(snap))
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def verify_grant(grant_env: dict, authorizer_pub: Ed25519PublicKey,
                 action: Optional[dict] = None, now: Optional[float] = None,
                 expected_tenant: Optional[str] = None,
                 action_bytes: Optional[bytes] = None) -> Check:
    """Independent authority check performed by the executor itself.

    The envelope is snapshotted once (snapshot_envelope) and only the snapshot is
    verified; on success the returned Check carries the frozen verified Grant and
    the snapshot, and callers must use those rather than re-reading `grant_env`.

    Pass `action_bytes` (a snapshot of `canon(action)` taken once) to bind the
    check to the EXACT bytes that will be dispatched; this closes a time-of-check /
    time-of-use gap where a mutable `action` dict is altered after validation but
    before dispatch. `action` is accepted for convenience and canonicalised here
    only when `action_bytes` is not supplied."""
    now = time.time() if now is None else now
    snapshot = snapshot_envelope(grant_env)
    payload = None if snapshot is None else verify_envelope(snapshot, authorizer_pub, GRANT_TYPE)
    if payload is None:
        return Check(False, "grant-signature-invalid")
    try:
        g = Grant(**payload)
    except TypeError:
        return Check(False, "grant-malformed")
    if now > g.expires_at:
        return Check(False, "grant-expired")
    # bind to the EXACT action being executed — catches a swapped/altered request
    digest = sha256_hex(action_bytes) if action_bytes is not None else action_digest(action)
    if digest != g.action_digest:
        return Check(False, "action-digest-mismatch")
    if expected_tenant is not None and g.tenant != expected_tenant:
        return Check(False, "wrong-tenant")
    return Check(True, grant=g, envelope=snapshot)


# ---------------------------------------------------------------- durable stores
class ProviderUnavailable(Exception):
    """The external service failed to return a definitive response (timeout / 5xx /
    lost response). The effect may or may not have happened — the executor must
    preserve this uncertainty and never report success."""


class ExternalWorld:
    """A SEPARATE durable system that performs effects at-most-once per idempotency
    key (models a real external API's own idempotency, e.g. a payment key)."""

    def __init__(self, path: str):
        self.path = path
        c = sqlite3.connect(path, timeout=30)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=FULL")
        c.execute(
            "CREATE TABLE IF NOT EXISTS effects("
            "idempotency_key TEXT PRIMARY KEY, attempt_id TEXT, target TEXT, "
            "payload_sha256 TEXT, effect_id TEXT UNIQUE, created_at REAL)"
        )
        c.commit()
        c.close()

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=30)
        c.execute("PRAGMA synchronous=FULL")
        c.row_factory = sqlite3.Row
        return c

    def apply(self, idempotency_key: str, attempt_id: str, target: str,
              payload: bytes, fault: Optional[str] = None) -> tuple[bool, str]:
        """Perform the external effect. Returns (created, effect_id). A duplicate
        idempotency key performs NO second effect and returns the existing id.
        `fault` models a provider failure and raises ProviderUnavailable:
        'fail_before_commit' (no effect happened) or 'lose_response_after_commit'
        (the effect IS committed but no definitive response is returned)."""
        effect_id = sha256_hex(b"effect:" + idempotency_key.encode())[:16]
        if fault == "fail_before_commit":
            raise ProviderUnavailable("provider error before commit")
        c = self._conn()
        try:
            c.execute(
                "INSERT INTO effects VALUES(?,?,?,?,?,?)",
                (idempotency_key, attempt_id, target, sha256_hex(payload), effect_id, time.time()),
            )
            c.commit()
            if fault == "lose_response_after_commit":
                raise ProviderUnavailable("response lost after commit")
            return True, effect_id
        except sqlite3.IntegrityError:
            row = c.execute(
                "SELECT effect_id FROM effects WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            return False, (row["effect_id"] if row else effect_id)
        finally:
            c.close()

    def get(self, idempotency_key: str) -> Optional[dict]:
        c = self._conn()
        try:
            row = c.execute(
                "SELECT * FROM effects WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            c.close()

    def count(self, attempt_id: Optional[str] = None) -> int:
        c = self._conn()
        try:
            if attempt_id is None:
                return c.execute("SELECT COUNT(*) FROM effects").fetchone()[0]
            return c.execute(
                "SELECT COUNT(*) FROM effects WHERE attempt_id=?", (attempt_id,)
            ).fetchone()[0]
        finally:
            c.close()

    def all(self) -> list[dict]:
        c = self._conn()
        try:
            return [dict(r) for r in c.execute("SELECT * FROM effects").fetchall()]
        finally:
            c.close()


# authority state machine
AVAILABLE = "AVAILABLE"
CLAIMED = "CLAIMED"
DISPATCH_AUTHORIZED = "DISPATCH_AUTHORIZED"
CLOSED = "CLOSED"
# terminal reconciliation verdicts
COMMITTED = "COMMITTED"
KNOWN_NOT_DISPATCHED = "KNOWN_NOT_DISPATCHED"
EFFECT_CONFLICT = "EFFECT_CONFLICT"   # an effect exists under the key but its
                                      # target/payload does not match the grant


class AuthorityLedger:
    """Durable governance ledger. Atomic single-use claim + append-only receipts."""

    def __init__(self, path: str):
        self.path = path
        c = sqlite3.connect(path, timeout=30)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=FULL")
        c.execute(
            "CREATE TABLE IF NOT EXISTS authority("
            "attempt_id TEXT PRIMARY KEY, allowance_id TEXT, action_digest TEXT, "
            "target TEXT, state TEXT, verdict TEXT, grant_env TEXT, "
            "created_at REAL, claimed_at REAL, dispatched_at REAL, closed_at REAL)"
        )
        c.execute("CREATE TABLE IF NOT EXISTS seen_nonce(nonce TEXT PRIMARY KEY, attempt_id TEXT)")
        c.execute(
            "CREATE TABLE IF NOT EXISTS receipts("
            "attempt_id TEXT PRIMARY KEY, envelope TEXT, created_at REAL)"
        )
        c.commit()
        c.close()

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=30)
        c.execute("PRAGMA synchronous=FULL")
        c.row_factory = sqlite3.Row
        return c

    def register(self, grant_env: dict):
        g = json.loads(grant_env["payload"])
        c = self._conn()
        try:
            c.execute(
                "INSERT OR IGNORE INTO authority(attempt_id, allowance_id, action_digest, "
                "target, state, grant_env, created_at) VALUES(?,?,?,?,?,?,?)",
                (g["attempt_id"], g["allowance_id"], g["action_digest"], g["target"],
                 AVAILABLE, json.dumps(grant_env), time.time()),
            )
            c.commit()
        finally:
            c.close()

    def consume_nonce_and_claim(self, nonce: str, attempt_id: str, *,
                                grant: Optional[Grant] = None,
                                grant_env: Optional[dict] = None) -> str:
        """Atomically consume the single-use nonce AND claim AVAILABLE -> CLAIMED in
        ONE transaction. Folding these together closes the gap dot reported: with two
        separate commits, a hard exit between them left the nonce burned while the
        attempt stayed AVAILABLE, so it could never be retried. As one transaction the
        only durable outcomes are 'nothing happened' or 'both happened'.

        When the verified `grant` is supplied, its identity (action digest, target,
        allowance) must equal the registered authority row, and the winning verified
        envelope snapshot replaces the stored one, so ledger, receipt and effect all
        bind to the grant that actually claimed the attempt.

        Returns 'ok' (this caller won), 'replay' (nonce already seen), 'not-claimable'
        (attempt missing or not AVAILABLE — another caller won the CAS) or
        'grant-authority-mismatch'. Exactly one concurrent caller gets 'ok'
        (BEGIN IMMEDIATE serialises writers)."""
        c = self._conn()
        c.isolation_level = None   # manual transaction control (literal BEGIN/COMMIT)
        try:
            c.execute("BEGIN IMMEDIATE")
            try:
                c.execute("INSERT INTO seen_nonce VALUES(?,?)", (nonce, attempt_id))
            except sqlite3.IntegrityError:
                c.execute("ROLLBACK")
                return "replay"
            row = c.execute(
                "SELECT state, action_digest, target, allowance_id FROM authority "
                "WHERE attempt_id=?", (attempt_id,),
            ).fetchone()
            if row is None or row["state"] != AVAILABLE:
                c.execute("ROLLBACK")   # also un-burns this caller's nonce attempt
                return "not-claimable"
            if grant is not None and (grant.action_digest, grant.target, grant.allowance_id) != (
                    row["action_digest"], row["target"], row["allowance_id"]):
                c.execute("ROLLBACK")
                return "grant-authority-mismatch"
            stored_env = None if grant_env is None else json.dumps(grant_env)
            c.execute(
                "UPDATE authority SET state=?, claimed_at=?, grant_env=COALESCE(?, grant_env) "
                "WHERE attempt_id=? AND state=?",
                (CLAIMED, time.time(), stored_env, attempt_id, AVAILABLE),
            )
            c.execute("COMMIT")
            return "ok"
        finally:
            c.close()

    def all_nonces(self) -> list[dict]:
        c = self._conn()
        try:
            return [dict(r) for r in c.execute("SELECT * FROM seen_nonce").fetchall()]
        finally:
            c.close()

    def mark_dispatch_authorized(self, attempt_id: str) -> bool:
        """Compare-and-swap CLAIMED -> DISPATCH_AUTHORIZED. Returns False if the
        attempt is no longer CLAIMED (e.g. closed out of band); the executor must then
        not dispatch."""
        c = self._conn()
        try:
            cur = c.execute(
                "UPDATE authority SET state=?, dispatched_at=? WHERE attempt_id=? AND state=?",
                (DISPATCH_AUTHORIZED, time.time(), attempt_id, CLAIMED),
            )
            c.commit()
            return cur.rowcount == 1
        finally:
            c.close()

    def finalize(self, attempt_id: str, state: str, verdict: str,
                 expected_states: Optional[list[str]] = None) -> bool:
        """Set the terminal state/verdict. With `expected_states` this is a
        compare-and-swap that only applies while the attempt is still in one of those
        states; returns whether it applied."""
        c = self._conn()
        try:
            if expected_states is None:
                cur = c.execute(
                    "UPDATE authority SET state=?, verdict=?, closed_at=? WHERE attempt_id=?",
                    (state, verdict, time.time(), attempt_id),
                )
            else:
                cur = c.execute(
                    "UPDATE authority SET state=?, verdict=?, closed_at=? WHERE attempt_id=? "
                    "AND state IN (%s)" % ",".join("?" * len(expected_states)),
                    (state, verdict, time.time(), attempt_id, *expected_states),
                )
            c.commit()
            return cur.rowcount == 1
        finally:
            c.close()

    def record_receipt(self, attempt_id: str, env: dict):
        c = self._conn()
        try:
            c.execute(
                "INSERT OR IGNORE INTO receipts VALUES(?,?,?)",
                (attempt_id, json.dumps(env), time.time()),
            )
            c.commit()
        finally:
            c.close()

    def row(self, attempt_id: str) -> Optional[dict]:
        c = self._conn()
        try:
            r = c.execute("SELECT * FROM authority WHERE attempt_id=?", (attempt_id,)).fetchone()
            return dict(r) if r else None
        finally:
            c.close()

    def in_states(self, states: list[str]) -> list[dict]:
        q = "SELECT * FROM authority WHERE state IN (%s)" % ",".join("?" * len(states))
        c = self._conn()
        try:
            return [dict(r) for r in c.execute(q, states).fetchall()]
        finally:
            c.close()

    def all_authority(self) -> list[dict]:
        c = self._conn()
        try:
            return [dict(r) for r in c.execute("SELECT * FROM authority").fetchall()]
        finally:
            c.close()

    def all_receipts(self) -> list[dict]:
        c = self._conn()
        try:
            return [dict(r) for r in c.execute("SELECT * FROM receipts").fetchall()]
        finally:
            c.close()


# ---------------------------------------------------------------- executor
class CrashInjected(BaseException):
    """Raised to simulate a hard crash at an injection point (see crash_worker)."""


@dataclass
class Outcome:
    status: str          # COMMITTED | REJECTED | KNOWN_NOT_DISPATCHED
    reason: str = ""
    effect_id: str = ""
    created_effect: bool = False


class GovernedExecutor:
    def __init__(self, ledger: AuthorityLedger, world: ExternalWorld,
                 authorizer_pub: Ed25519PublicKey, exec_priv: Ed25519PrivateKey):
        self.ledger = ledger
        self.world = world
        self.authorizer_pub = authorizer_pub
        self.exec_priv = exec_priv
        self.lock_timeout_s = 30.0   # how long execute() waits for an attempt's lock

    def _receipt(self, grant: dict, effect_id: str, verdict: str) -> dict:
        payload = {
            "attempt_id": grant["attempt_id"],
            "action_digest": grant["action_digest"],
            "target": grant["target"],
            "allowance_id": grant["allowance_id"],
            "policy_revision": grant["policy_revision"],
            "effect_id": effect_id,
            "verdict": verdict,
            "observed_at": time.time(),
        }
        return sign_envelope(payload, self.exec_priv, ENVELOPE_TYPE)

    def _effect_conflict(self, aid: str, grant: dict) -> Optional[str]:
        """Reconcile the external effect's identity/content against the signed grant.
        Returns a reason string if an effect exists under this key whose target or
        payload does NOT match the grant (so it must never be reported COMMITTED),
        else None. grant['action_digest'] == sha256(canon(authorized action)); the
        external store records payload_sha256 over the dispatched bytes."""
        e = self.world.get(aid)
        if e is None:
            return "effect-missing"
        if e["target"] != grant["target"] or e["payload_sha256"] != grant["action_digest"]:
            return "idempotency-key-conflict"
        return None

    @contextmanager
    def _attempt_lock(self, aid: str, timeout_s: float):
        """Per-attempt dispatch lock: an exclusive SQLite lock on a small per-attempt
        lock file next to the ledger. The executor holds it from claim to close;
        recovery only resolves an attempt while holding it, so recovery can never
        observe a live dispatch half-way. The OS releases the lock when a process
        dies, so a crashed executor never blocks recovery. Yields True if acquired.

        Limits: a provider call that hangs keeps ITS attempt locked (recovery skips
        that attempt until the call returns or the process exits) but blocks no other
        attempt; file locks are host-local, so this fences processes on one host."""
        lock_dir = self.ledger.path + ".locks"
        os.makedirs(lock_dir, exist_ok=True)
        path = os.path.join(lock_dir, sha256_hex(aid.encode())[:32] + ".lock")
        conn = sqlite3.connect(path, timeout=timeout_s, isolation_level=None)
        try:
            try:
                conn.execute("BEGIN EXCLUSIVE")
            except sqlite3.OperationalError:
                yield False
                return
            try:
                yield True
            finally:
                conn.execute("ROLLBACK")
        finally:
            conn.close()

    def execute(self, action: dict, grant_env: dict, *, now: Optional[float] = None,
                crash_hook=None, expected_tenant: Optional[str] = None,
                provider_fault: Optional[str] = None) -> Outcome:
        def crash(point):
            if crash_hook:
                crash_hook(point)

        # 0. SNAPSHOT the caller's action ONCE. These exact bytes are used for the
        #    authority check AND the dispatch payload; `action` is never
        #    re-canonicalised afterwards, so mutating the caller's dict after this
        #    point cannot change what was authorised or what is dispatched.
        action_bytes = canon(action)

        # 1. INDEPENDENT authority check over a once-read snapshot of the envelope.
        #    From here on only the frozen verified grant is used; `grant_env` is never
        #    read again, so it cannot supply an unverified target or identity.
        chk = verify_grant(grant_env, self.authorizer_pub, now=now,
                           expected_tenant=expected_tenant, action_bytes=action_bytes)
        if not chk.ok:
            return Outcome("REJECTED", chk.reason)          # zero effect
        verified = chk.grant
        grant = verified.body()
        aid = verified.attempt_id

        with self._attempt_lock(aid, self.lock_timeout_s) as locked:
            if not locked:
                return Outcome("REJECTED", "attempt-in-flight")   # zero effect by this caller

            # 2+3. atomic single-use: consume the nonce AND claim in ONE transaction,
            #      bound to the registered authority row. Losers never dispatch.
            status = self.ledger.consume_nonce_and_claim(
                verified.nonce, aid, grant=verified, grant_env=chk.envelope)
            if status == "replay":
                return Outcome("REJECTED", "replay-nonce")    # zero new effect
            if status == "grant-authority-mismatch":
                return Outcome("REJECTED", status)
            if status != "ok":
                return Outcome("REJECTED", "not-available-or-already-claimed")
            crash("after_claim")

            # 4. durably record intent-to-dispatch BEFORE touching the external world
            #    (CAS: if the attempt was closed out of band, do not dispatch).
            if not self.ledger.mark_dispatch_authorized(aid):
                return Outcome("REJECTED", "fenced-before-dispatch")
            crash("after_dispatch_authorized")

            # 5. idempotent external effect (at-most-once by key), dispatching the
            #    exact snapshotted bytes to the verified target.
            try:
                created, effect_id = self.world.apply(
                    idempotency_key=aid, attempt_id=aid, target=verified.target,
                    payload=action_bytes, fault=provider_fault,
                )
            except ProviderUnavailable as exc:
                # No definitive response: the effect may or may not have happened.
                # Do NOT claim success; leave the attempt DISPATCH_AUTHORIZED (durable)
                # so recovery resolves it by external readback once this lock is free.
                return Outcome("UNKNOWN", f"provider-unavailable: {exc}")

            # 5a. reconcile effect identity/content against the grant. An effect already
            #     present under this key with a different target/payload is NEVER success.
            conflict = self._effect_conflict(aid, grant)
            if conflict is not None:
                self.ledger.finalize(aid, CLOSED, EFFECT_CONFLICT,
                                     expected_states=[DISPATCH_AUTHORIZED])
                return Outcome("REJECTED", conflict)
            crash("after_effect_before_receipt")

            # 6. bind a signed receipt to the REAL effect, then close (CAS)
            env = self._receipt(grant, effect_id, COMMITTED)
            self.ledger.record_receipt(aid, env)
            if not self.ledger.finalize(aid, CLOSED, COMMITTED,
                                        expected_states=[DISPATCH_AUTHORIZED]):
                return Outcome("UNKNOWN", "finalize-fenced", effect_id, created)
            crash("after_close_before_return")
            return Outcome("COMMITTED", "ok", effect_id, created)

    def recover(self, lock_timeout_s: float = 0.0) -> list[tuple[str, str]]:
        """Resolve interrupted attempts by reading the EXTERNAL world — never by
        guessing — and only while holding the attempt's dispatch lock. An attempt
        whose lock is held by a live executor is skipped and stays recoverable, so a
        recovery pass that overlaps a dispatch can never close it prematurely.

        CLAIMED/DISPATCH_AUTHORIZED with no effect -> KNOWN_NOT_DISPATCHED
        (consumption retained, NO resend). With a matching effect -> COMMITTED (bind
        the receipt to the real effect). A mismatched effect -> EFFECT_CONFLICT. An
        uncertain state never becomes a success claim without a confirmed effect."""
        resolved = []
        open_states = [CLAIMED, DISPATCH_AUTHORIZED]
        for listed in self.ledger.in_states(open_states):
            aid = listed["attempt_id"]
            with self._attempt_lock(aid, lock_timeout_s) as locked:
                if not locked:
                    continue                      # live dispatch in progress
                row = self.ledger.row(aid)        # re-read under the lock
                if row is None or row["state"] not in open_states:
                    continue
                stored = verify_envelope(json.loads(row["grant_env"]),
                                         self.authorizer_pub, GRANT_TYPE)
                if stored is None:
                    continue                      # tampered grant: leave for the verifier
                effect = self.world.get(aid)
                if effect is None:
                    if self.ledger.finalize(aid, CLOSED, KNOWN_NOT_DISPATCHED,
                                            expected_states=open_states):
                        resolved.append((aid, KNOWN_NOT_DISPATCHED))
                    continue
                # reconcile the real effect's content against the signed grant before
                # claiming success — never promote a mismatched effect to COMMITTED.
                if (effect["target"] != stored["target"]
                        or effect["payload_sha256"] != stored["action_digest"]):
                    if self.ledger.finalize(aid, CLOSED, EFFECT_CONFLICT,
                                            expected_states=open_states):
                        resolved.append((aid, EFFECT_CONFLICT))
                    continue
                env = self._receipt(stored, effect["effect_id"], COMMITTED)
                self.ledger.record_receipt(aid, env)
                if self.ledger.finalize(aid, CLOSED, COMMITTED, expected_states=open_states):
                    resolved.append((aid, COMMITTED))
        return resolved


# ---------------------------------------------------------------- independent verifier
@dataclass
class Invariant:
    name: str
    ok: bool
    detail: str = ""


def independent_verify(ledger: AuthorityLedger, world: ExternalWorld,
                       authorizer_pub: Ed25519PublicKey,
                       exec_pub: Ed25519PublicKey) -> list[Invariant]:
    """Zero-trust reconciliation: read the external world + the signed receipts +
    the authority ledger and check they agree. Does not trust the executor."""
    inv: list[Invariant] = []
    effects = {e["attempt_id"]: e for e in world.all()}
    effects_list = world.all()
    authority = {a["attempt_id"]: a for a in ledger.all_authority()}
    receipts = {r["attempt_id"]: json.loads(r["envelope"]) for r in ledger.all_receipts()}

    # I1: at most one external effect per attempt (unique key); counts reconcile
    per_attempt_ok = len(effects_list) == len(effects)
    inv.append(Invariant("at_most_one_effect_per_attempt", per_attempt_ok,
                         f"{len(effects_list)} effects / {len(effects)} distinct attempts"))

    # I2: every effect traces to an authorized attempt whose verdict is COMMITTED
    bad = [e["attempt_id"] for e in effects_list
           if e["attempt_id"] not in authority
           or authority[e["attempt_id"]].get("verdict") != COMMITTED]
    inv.append(Invariant("no_effect_without_committed_authority", not bad,
                         f"unauthorized effects: {bad}"))

    # I3: no effect exists for a rejected / never-claimed / KNOWN_NOT_DISPATCHED attempt
    leaked = []
    for aid, a in authority.items():
        if a.get("verdict") == KNOWN_NOT_DISPATCHED and aid in effects:
            leaked.append(aid)
    inv.append(Invariant("no_effect_for_not_dispatched", not leaked,
                         f"leaked effects: {leaked}"))

    # I4: every receipt signature verifies, binds to a REAL external effect, and its
    #     action_digest matches the authority row (no success claim without evidence)
    bad_receipts = []
    for aid, env in receipts.items():
        payload = verify_envelope(env, exec_pub, ENVELOPE_TYPE)
        if payload is None:
            bad_receipts.append((aid, "signature"))
            continue
        if payload.get("verdict") == COMMITTED:
            e = effects.get(aid)
            if e is None or e["effect_id"] != payload.get("effect_id"):
                bad_receipts.append((aid, "receipt-without-real-effect"))
            elif e["target"] != payload.get("target") or e["payload_sha256"] != payload.get("action_digest"):
                # the real effect's target/content disagrees with what the receipt claims
                bad_receipts.append((aid, "effect-content-mismatch"))
            elif aid in authority and payload.get("action_digest") != authority[aid]["action_digest"]:
                bad_receipts.append((aid, "action-digest-mismatch"))
    inv.append(Invariant("every_committed_receipt_backed_by_effect", not bad_receipts,
                         f"bad receipts: {bad_receipts}"))

    # I5: every stored grant signature verifies under the authorizer key
    bad_grants = []
    for aid, a in authority.items():
        env = json.loads(a["grant_env"])
        if verify_envelope(env, authorizer_pub, GRANT_TYPE) is None:
            bad_grants.append(aid)
    inv.append(Invariant("all_grants_authorizer_signed", not bad_grants,
                         f"bad grants: {bad_grants}"))

    # I6: no attempt is left AVAILABLE while its single-use nonce is already consumed.
    #     The atomic nonce+claim makes this state unreachable; the verifier checks it.
    stranded = [n["attempt_id"] for n in ledger.all_nonces()
                if n["attempt_id"] in authority
                and authority[n["attempt_id"]]["state"] == AVAILABLE]
    inv.append(Invariant("no_consumed_nonce_with_available_attempt", not stranded,
                         f"stranded attempts: {stranded}"))

    # I7: every stored grant's SIGNED identity matches the authority row it governs
    #     (a signature check alone does not bind the grant to this ledger row).
    grants, unbound = {}, []
    for aid, a in authority.items():
        g = verify_envelope(json.loads(a["grant_env"]), authorizer_pub, GRANT_TYPE)
        if g is None:
            continue                                  # reported by I5
        grants[aid] = g
        if (g.get("attempt_id"), g.get("action_digest"), g.get("target"),
                g.get("allowance_id")) != (aid, a["action_digest"], a["target"], a["allowance_id"]):
            unbound.append(aid)
    inv.append(Invariant("grant_identity_bound_to_ledger", not unbound,
                         f"unbound grants: {unbound}"))

    # I8: EVERY signed receipt, whatever its verdict, agrees with the attempt it is
    #     stored under, the signed grant, the ledger verdict and the external effect.
    inconsistent = []
    for aid, env in receipts.items():
        p = verify_envelope(env, exec_pub, ENVELOPE_TYPE)
        if p is None:
            inconsistent.append((aid, "signature"))
            continue
        if p.get("attempt_id") != aid:
            inconsistent.append((aid, "identity-swap"))
            continue
        a, g = authority.get(aid), grants.get(aid)
        if a is None or g is None:
            inconsistent.append((aid, "receipt-without-verified-authority"))
            continue
        if any(p.get(k) != g.get(k) for k in ("action_digest", "target", "allowance_id",
                                               "policy_revision")):
            inconsistent.append((aid, "receipt-disagrees-with-signed-grant"))
            continue
        verdict = p.get("verdict")
        if verdict != a.get("verdict"):
            inconsistent.append((aid, "receipt-verdict-disagrees-with-ledger"))
            continue
        e = effects.get(aid)
        if verdict == COMMITTED:
            if (e is None or e["effect_id"] != p.get("effect_id")
                    or e["target"] != g["target"] or e["payload_sha256"] != g["action_digest"]):
                inconsistent.append((aid, "committed-receipt-effect-mismatch"))
        elif verdict == KNOWN_NOT_DISPATCHED:
            if e is not None:
                inconsistent.append((aid, "not-dispatched-receipt-but-effect-exists"))
        elif verdict == EFFECT_CONFLICT:
            if e is None or (e["target"] == g["target"] and e["payload_sha256"] == g["action_digest"]):
                inconsistent.append((aid, "conflict-receipt-without-conflicting-effect"))
        else:
            inconsistent.append((aid, "unknown-verdict"))
    inv.append(Invariant("every_receipt_consistent_with_ledger_and_grant", not inconsistent,
                         f"inconsistent receipts: {inconsistent}"))

    # I9: every COMMITTED ledger verdict is evidenced by a receipt
    unreceipted = [aid for aid, a in authority.items()
                   if a.get("verdict") == COMMITTED and aid not in receipts]
    inv.append(Invariant("every_committed_verdict_has_receipt", not unreceipted,
                         f"committed without receipt: {unreceipted}"))

    return inv
