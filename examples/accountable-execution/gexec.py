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
import math
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
        if not isinstance(json.loads(body), dict):
            return None
        # bind the signed bytes to the canonical form (no body-swap under a valid sig)
        if canon(json.loads(body)) != body:
            return None
        sig_entry = env["signatures"][0]
        if sig_entry.get("keyid") != key_id(trusted_pub):
            return None
        trusted_pub.verify(bytes.fromhex(sig_entry["sig"]), dsse_pae(payload_type, body))
        return json.loads(body)
    except (InvalidSignature, KeyError, ValueError, IndexError, TypeError, AttributeError,
            RecursionError):
        return None   # any malformed envelope is a rejection, never an exception


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
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
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
    if not valid_grant_shape(payload):
        return Check(False, "grant-malformed")
    if now > g.expires_at:
        return Check(False, "grant-expired")
    if now < g.issued_at:
        return Check(False, "grant-not-yet-valid")
    # bind to the EXACT action being executed — catches a swapped/altered request
    digest = sha256_hex(action_bytes) if action_bytes is not None else action_digest(action)
    if digest != g.action_digest:
        return Check(False, "action-digest-mismatch")
    if expected_tenant is not None and g.tenant != expected_tenant:
        return Check(False, "wrong-tenant")
    return Check(True, grant=g, envelope=snapshot)


def finite_number(value) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        return False


def valid_grant_shape(payload: dict) -> bool:
    try:
        grant = Grant(**payload)
    except (TypeError, ValueError):
        return False
    fields = (grant.proposal_id, grant.action_digest, grant.target, grant.tenant,
              grant.policy_revision, grant.allowance_id, grant.attempt_id, grant.nonce)
    return (all(isinstance(value, str) and value for value in fields)
            and len(grant.action_digest) == 64
            and all(c in "0123456789abcdef" for c in grant.action_digest)
            and finite_number(grant.issued_at) and finite_number(grant.expires_at))


def stored_grant(raw, authorizer_pub) -> Optional[dict]:
    payload = verify_envelope(stored_envelope(raw), authorizer_pub, GRANT_TYPE)
    return payload if payload is not None and valid_grant_shape(payload) else None


def valid_window(grant: dict) -> bool:
    """Only finite numeric, ordered grant timestamps define an authority window."""
    values = (grant.get("issued_at"), grant.get("expires_at"))
    return (all(finite_number(v) for v in values)
            and values[0] <= values[1])


def dispatch_in_window(row: dict, grant: dict) -> bool:
    stamp = row.get("dispatched_at")
    return (valid_window(grant) and finite_number(stamp)
            and grant["issued_at"] <= stamp <= grant["expires_at"])


def grant_bound_to_row(grant: dict, row: dict) -> bool:
    return all(grant.get(k) == row.get(k) for k in (
        "attempt_id", "action_digest", "target", "allowance_id", "tenant", "policy_revision"))


def stored_envelope(raw):
    try:
        return json.loads(raw)
    except (TypeError, ValueError, RecursionError):
        return None


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
            "created_at REAL, claimed_at REAL, dispatched_at REAL, closed_at REAL, "
            "tenant TEXT, policy_revision TEXT)"
        )
        # Existing demo ledgers retain unknown identities rather than deriving trust
        # from replaceable envelope bytes. Such rows fail closed and need re-issuance.
        columns = {r[1] for r in c.execute("PRAGMA table_info(authority)")}
        for field in ("tenant", "policy_revision"):
            if field not in columns:
                c.execute(f"ALTER TABLE authority ADD COLUMN {field} TEXT")
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
                "target, state, grant_env, created_at, tenant, policy_revision) VALUES(?,?,?,?,?,?,?,?,?)",
                (g["attempt_id"], g["allowance_id"], g["action_digest"], g["target"],
                 AVAILABLE, json.dumps(grant_env), time.time(), g["tenant"], g["policy_revision"]),
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
                "SELECT * FROM authority "
                "WHERE attempt_id=?", (attempt_id,),
            ).fetchone()
            if row is None or row["state"] != AVAILABLE:
                c.execute("ROLLBACK")   # also un-burns this caller's nonce attempt
                return "not-claimable"
            if grant is not None and not grant_bound_to_row(grant.body(), dict(row)):
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

    def mark_dispatch_authorized(self, attempt_id: str, grant: Grant) -> bool:
        """Compare-and-swap CLAIMED -> DISPATCH_AUTHORIZED. Returns False if the
        attempt is no longer CLAIMED (e.g. closed out of band); the executor must then
        not dispatch."""
        c = self._conn()
        try:
            c.execute("BEGIN IMMEDIATE")
            stamp = time.time()  # evaluate AFTER waiting for the database writer lock
            if not grant.issued_at <= stamp <= grant.expires_at:
                c.rollback()
                return False
            cur = c.execute(
                "UPDATE authority SET state=?, dispatched_at=? WHERE attempt_id=? AND state=?",
                (DISPATCH_AUTHORIZED, stamp, attempt_id, CLAIMED),
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

    def nonce_seen(self, nonce: str) -> bool:
        """Read-only, non-authoritative fast path for rejecting an obvious replay
        before waiting on a dispatch lock. The authoritative check stays inside
        consume_nonce_and_claim."""
        c = self._conn()
        try:
            return c.execute("SELECT 1 FROM seen_nonce WHERE nonce=?", (nonce,)).fetchone() is not None
        finally:
            c.close()

    def close_with_receipt(self, attempt_id: str, env: dict, verdict: str,
                           expected_states: list[str]) -> bool:
        """Atomically close the attempt with `verdict` AND record its signed receipt in
        ONE ledger transaction (receipts live in the same database). If the attempt is
        no longer in `expected_states` nothing is written, so a fenced close can never
        leave a receipt that contradicts the ledger, and a crash can never leave a
        COMMITTED verdict without its receipt."""
        c = self._conn()
        c.isolation_level = None
        try:
            c.execute("BEGIN IMMEDIATE")
            cur = c.execute(
                "UPDATE authority SET state=?, verdict=?, closed_at=? WHERE attempt_id=? "
                "AND state IN (%s)" % ",".join("?" * len(expected_states)),
                (CLOSED, verdict, time.time(), attempt_id, *expected_states),
            )
            if cur.rowcount != 1:
                c.execute("ROLLBACK")
                return False
            try:
                c.execute("INSERT INTO receipts VALUES(?,?,?)",
                          (attempt_id, json.dumps(env), time.time()))
            except sqlite3.IntegrityError:
                c.execute("ROLLBACK")
                return False
            c.execute("COMMIT")
            return True
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

    def verification_snapshot(self) -> tuple[list[dict], list[dict], list[dict]]:
        """Read authority, receipts and nonce consumption in one SQLite snapshot."""
        c = self._conn()
        try:
            c.execute("BEGIN")
            return tuple([dict(r) for r in c.execute(f"SELECT * FROM {table}")]
                         for table in ("authority", "receipts", "seen_nonce"))
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
        self.last_recovery_skipped: list[tuple[str, str]] = []

    def _receipt(self, grant: dict, effect_id: str, verdict: str) -> dict:
        payload = {
            "attempt_id": grant["attempt_id"],
            "action_digest": grant["action_digest"],
            "target": grant["target"],
            "tenant": grant["tenant"],
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
        if (e["idempotency_key"] != aid or e["attempt_id"] != aid
                or e["target"] != grant["target"] or e["payload_sha256"] != grant["action_digest"]):
            return "idempotency-key-conflict"
        return None

    def _lock_path(self, aid: str) -> str:
        """Per-attempt lock file, keyed on the ledger's real path and (device, inode)."""
        real = os.path.realpath(self.ledger.path)
        st = os.stat(real)
        lock_dir = os.path.join(os.path.dirname(real), f".gexec-locks-{st.st_dev}-{st.st_ino}")
        os.makedirs(lock_dir, exist_ok=True)
        return os.path.join(lock_dir, sha256_hex(aid.encode())[:32] + ".lock")

    @contextmanager
    def _attempt_lock(self, aid: str, timeout_s: float):
        """Per-attempt dispatch lock: an exclusive SQLite lock on a small per-attempt
        lock file next to the ledger. The executor holds it from claim to close;
        recovery only resolves an attempt while holding it, so recovery can never
        observe a live dispatch half-way. The OS releases the lock when a process
        dies, so a crashed executor never blocks recovery. Yields True if acquired.

        The lock directory is keyed on the ledger's resolved real path and its
        (device, inode), so a symlinked path or a same-directory hard link to the same
        ledger shares one lock. Yields "acquired", "busy" (another holder) or
        "unusable" (lock file cannot be used, e.g. not a SQLite file); only
        "acquired" permits work.

        Limits: a provider call that hangs keeps ITS attempt locked (recovery skips
        that attempt until the call returns or the process exits) but blocks no other
        attempt; file locks are host-local, so this fences processes on one host;
        and on POSIX any other open()+close() of a lock file inside the holder's own
        process silently drops its lock, so nothing else may open these files."""
        # A hard-linked ledger has more than one directory entry; aliases in other
        # directories would derive different lock directories (and SQLite itself does
        # not support hard-linked databases: journal/WAL files are named by path).
        # Refuse to admit or recover through it rather than fence incompletely.
        try:
            if os.stat(os.path.realpath(self.ledger.path)).st_nlink != 1:
                yield "unusable"
                return
            path = self._lock_path(aid)
            conn = sqlite3.connect(path, timeout=timeout_s, isolation_level=None)
        except (OSError, sqlite3.Error):
            yield "unusable"
            return
        try:
            try:
                conn.execute("BEGIN EXCLUSIVE")
            except sqlite3.OperationalError:
                yield "busy"
                return
            except sqlite3.DatabaseError:
                yield "unusable"
                return
            try:
                yield "acquired"
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
        # The legacy `now` request argument is deliberately ignored: execution
        # authority always uses the local trusted clock, including after lock waits.
        chk = verify_grant(grant_env, self.authorizer_pub,
                           expected_tenant=expected_tenant, action_bytes=action_bytes)
        if not chk.ok:
            return Outcome("REJECTED", chk.reason)          # zero effect
        verified = chk.grant
        grant = verified.body()
        aid = verified.attempt_id

        # Fast path: an already-consumed nonce is rejected without waiting on the
        # attempt's dispatch lock (the authoritative check stays inside the claim).
        if self.ledger.nonce_seen(verified.nonce):
            return Outcome("REJECTED", "replay-nonce")

        with self._attempt_lock(aid, self.lock_timeout_s) as lock:
            if lock == "busy":
                return Outcome("REJECTED", "attempt-in-flight")   # zero effect by this caller
            if lock != "acquired":
                return Outcome("REJECTED", "attempt-lock-unavailable")

            # Waiting for the lock takes time: re-check expiry at admission.
            stamp = time.time()
            if not verified.issued_at <= stamp <= verified.expires_at:
                return Outcome("REJECTED", "grant-expired")

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
            if not self.ledger.mark_dispatch_authorized(aid, verified):
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

            # 6. bind a signed receipt to the REAL effect and close, atomically (CAS):
            #    if the attempt was closed out of band, no receipt is written and the
            #    outcome stays UNKNOWN for the independent verifier to reconcile.
            env = self._receipt(grant, effect_id, COMMITTED)
            if not self.ledger.close_with_receipt(aid, env, COMMITTED,
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
        uncertain state never becomes a success claim without a confirmed effect.

        Attempts left open are reported in `self.last_recovery_skipped` as
        (attempt_id, reason): "in-flight", "lock-unusable" or
        "stored-grant-unverifiable" (e.g. tampered, or signed by a rotated-out key)."""
        resolved = []
        self.last_recovery_skipped = []
        open_states = [CLAIMED, DISPATCH_AUTHORIZED]
        for listed in self.ledger.in_states(open_states):
            aid = listed["attempt_id"]
            with self._attempt_lock(aid, lock_timeout_s) as lock:
                if lock != "acquired":            # live dispatch, or an unusable lock file:
                    self.last_recovery_skipped.append(   # skip THIS attempt only
                        (aid, "in-flight" if lock == "busy" else "lock-unusable"))
                    continue
                row = self.ledger.row(aid)        # re-read under the lock
                if row is None or row["state"] not in open_states:
                    continue
                stored = stored_grant(row["grant_env"], self.authorizer_pub)
                if stored is None or not grant_bound_to_row(stored, row):
                    self.last_recovery_skipped.append((aid, "stored-grant-unverifiable"))
                    continue                      # left for the independent verifier
                effect = self.world.get(aid)
                if effect is None:
                    if self.ledger.finalize(aid, CLOSED, KNOWN_NOT_DISPATCHED,
                                            expected_states=open_states):
                        resolved.append((aid, KNOWN_NOT_DISPATCHED))
                    continue
                if not dispatch_in_window(row, stored):
                    self.last_recovery_skipped.append((aid, "invalid-dispatch-authorization"))
                    continue
                # reconcile the real effect's content against the signed grant before
                # claiming success — never promote a mismatched effect to COMMITTED.
                if (effect["idempotency_key"] != aid or effect["attempt_id"] != aid
                        or effect["target"] != stored["target"]
                        or effect["payload_sha256"] != stored["action_digest"]):
                    if self.ledger.finalize(aid, CLOSED, EFFECT_CONFLICT,
                                            expected_states=open_states):
                        resolved.append((aid, EFFECT_CONFLICT))
                    continue
                env = self._receipt(stored, effect["effect_id"], COMMITTED)
                if self.ledger.close_with_receipt(aid, env, COMMITTED, expected_states=open_states):
                    resolved.append((aid, COMMITTED))
        return resolved


# ---------------------------------------------------------------- independent verifier
@dataclass
class Invariant:
    name: str
    ok: Optional[bool]   # True=verified, False=violation, None=unresolved/in-flight
    detail: str = ""


def independent_verify(ledger: AuthorityLedger, world: ExternalWorld,
                       authorizer_pub: Ed25519PublicKey,
                       exec_pub: Ed25519PublicKey) -> list[Invariant]:
    """Zero-trust reconciliation: read the external world + the signed receipts +
    the authority ledger and check they agree. Does not trust the executor."""
    inv: list[Invariant] = []
    # Bracket the external read with consistent ledger snapshots. A completed row
    # guarantees its effect was already committed; a changing ledger is retried.
    # No claim of atomicity across the two stores is made.
    for _ in range(3):
        before = ledger.verification_snapshot()
        effects_list = world.all()
        after = ledger.verification_snapshot()
        if before == after:
            break
    else:
        return [Invariant("verification_snapshot_stable", None,
                          "unresolved: ledger changed during verification; retry")]
    rows, receipt_rows, nonces = after
    authority = {a["attempt_id"]: a for a in rows}
    effects = {e["idempotency_key"]: e for e in effects_list}
    receipts = {r["attempt_id"]: stored_envelope(r["envelope"]) for r in receipt_rows}
    grants = {aid: stored_grant(a["grant_env"], authorizer_pub)
              for aid, a in authority.items()}

    # I1: the actual provider key must be the authorized attempt, not just metadata.
    attempts = {e["attempt_id"] for e in effects_list}
    key_ok = all(e["idempotency_key"] == e["attempt_id"] for e in effects_list)
    inv.append(Invariant("at_most_one_effect_per_attempt",
                         key_ok and len(effects_list) == len(attempts),
                         f"{len(effects_list)} effects / {len(attempts)} distinct attempts; key_binding={key_ok}"))

    # I2: closed effects require committed authority and a valid dispatch window.
    # A legitimate effect can precede its receipt: report unresolved, never tamper
    # and never verified success, until dispatch/recovery closes the attempt.
    bad = []
    pending = [aid for aid, a in authority.items()
               if a["state"] in (CLAIMED, DISPATCH_AUTHORIZED)]
    for e in effects_list:
        aid = e["idempotency_key"]
        a, g = authority.get(aid), grants.get(aid)
        if (a is None or g is None or e["attempt_id"] != aid
                or not grant_bound_to_row(g, a) or not dispatch_in_window(a, g)
                or (a["state"] != DISPATCH_AUTHORIZED and a.get("verdict") != COMMITTED)):
            bad.append(aid)
    inv.append(Invariant("no_effect_without_committed_authority",
                         False if bad else (None if pending else True),
                         f"unauthorized effects: {bad}; unresolved attempts: {pending}"))

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
    bad_grants = [aid for aid, g in grants.items() if g is None]
    inv.append(Invariant("all_grants_authorizer_signed", not bad_grants,
                         f"bad grants: {bad_grants}"))

    # I6: no attempt is left AVAILABLE while its single-use nonce is already consumed.
    #     The atomic nonce+claim makes this state unreachable; the verifier checks it.
    stranded = [n["attempt_id"] for n in nonces
                if n["attempt_id"] in authority
                and authority[n["attempt_id"]]["state"] == AVAILABLE]
    inv.append(Invariant("no_consumed_nonce_with_available_attempt", not stranded,
                         f"stranded attempts: {stranded}"))

    # I7: every stored grant's SIGNED identity matches the authority row it governs
    #     (a signature check alone does not bind the grant to this ledger row).
    unbound = [aid for aid, g in grants.items()
               if g is not None and not grant_bound_to_row(g, authority[aid])]
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
                                               "policy_revision", "tenant")):
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

