# Accountable AI Execution — tested reference implementation

A self-contained reference implementation of the governed-action chain, with a test
suite that exercises its properties under adversaries. It is **a tested reference
implementation under explicit assumptions — not a proof about any deployed system, and
not an unconditional guarantee.**

```
python3 prove.py                       # property suite (happy path + adversaries), 49 checks
python3 -m unittest test_negative -v   # independent negative/adversarial tests, 22 cases
python3 acceptance_matrix.py           # A–F acceptance matrix (30 named rows)
python3 acceptance_matrix.py --json    # same, regenerating DEMO_CASES.json
```

Python standard library + `cryptography` only. No network, no spend, no external
services, no deployment.

## The chain it models

> An agent proposes an action. A trusted policy signs a grant bound to the **exact**
> request. The executor **independently** re-checks that authority. The effect runs
> against a **separate durable external world** under an idempotency key. An
> **independent verifier** reconciles signed receipts against the real external state.

Policy (grant) → governed executor → external effect → receipt → independent verifier.

## Properties exercised by the tests

| Property | Adversary | Expected behaviour (asserted) |
|---|---|---|
| **1. Authority is exact & single-use** | wrong-digest, expired, or replayed grant | **zero** new effects |
| **2. At-most-once under concurrency** | N racing attempts on one grant | **exactly one** effect |
| **3. Crashes never fake success** | hard process death before/after dispatch | uncertain state is never a success claim; resolved only by external readback; no double effect on restart |
| **4. Independent reconciliation** | a forged effect or a tampered receipt | the verifier **detects** it; every committed receipt is backed by a real effect |
| **5. Composition integrity** | action mutated after validation; foreign effect under the key; crash between nonce and claim | the **snapshot** is dispatched (no TOCTOU); a key hit with different content is never `COMMITTED`; nonce-consume + claim are **atomic** so no attempt is stranded |
| **6. Grant binding & recovery fencing** | envelope payload changed after verification; distinct signed nonces on one attempt; recovery overlapping a live dispatch; receipts that contradict the grant, ledger or effect | only the **signed** target is dispatched; the claim CAS admits exactly one; recovery **skips** a live attempt instead of guessing, so a late provider commit still ends `COMMITTED`; every signed receipt, whatever its verdict, is reconciled |

`test_negative.py` runs the adversarial cases as standalone `unittest` cases,
independent of the `prove.py` harness, so the negative controls can be run and reviewed
on their own.

## The A–F acceptance matrix

`acceptance_matrix.py` runs **30 named, individually-labelled rows** grouped into six
families, each asserting the exact behaviour that must hold (and the things that must
*not* happen). `--json` writes the machine-readable outcomes to `DEMO_CASES.json`.

| Family | Rows | What it pins down |
|---|---|---|
| **A. Authority is exact & single-use** | A1–A9 | tampered-body, expired, missing-authority, wrong-tenant, replay, forged-signature → **zero** effect; **A7** action mutated after validation → the snapshot is dispatched, not the mutation; **A8** grant payload changed after verification → only the signed target is dispatched; **A9** signed grant that disagrees with the registered authority row → denied |
| **B. Concurrency & effect-identity** | B1–B4 | N racers on the same grant/nonce → at-most-one effect and **truthful losers**; same key / different payload → no second effect; **B4** 16 *distinct* signed nonces on one attempt → the claim CAS alone admits exactly one; **B3** existing key with a different target/payload → `EFFECT_CONFLICT`, never `COMMITTED` |
| **C. Crash safety** | C1–C7 | hard death at five points never turns an uncertain result into a success claim; **C5** crash between nonce and claim leaves a `CLAIMED`, recoverable attempt — never a stranded `AVAILABLE` one with a burned nonce; **C6** recovery overlapping a live dispatch whose provider commits but loses the response → skipped, then `COMMITTED`; **C7** attempt closed out of band after claim → dispatch fenced |
| **D. Provider faults** | D1–D2 | fault **before** commit → `UNKNOWN`, not-dispatched; commit **but response lost** → `UNKNOWN`, then `COMMITTED` by readback |
| **E. Verifier catches a liar** | E1–E7 | forged effect, tampered receipt, executor that *claims* success with no effect, **E4** real effect content altered after commit, **E5** receipt contradicting the signed grant, **E6** signed non-`COMMITTED` receipt contradicting the ledger/effect, **E7** receipt stored under another attempt's identity → **detected** |
| **F. Positive path** | F1 | authorized action → exactly one real effect, correct binding, all invariants clean |

The D family is the honesty core: a provider timeout or lost response is **never**
read as proof of cancellation or of success — the outcome stays `UNKNOWN` until the
external world is read back. Nothing is summed across families; each row stands alone.

### Review round 3 (independent review by `dot`) — closed here

Three correctness findings from an independent exact-head reproduction are fixed and
regression-covered: (1) **action snapshot** — `canon(action)` is taken once and reused
for the authority check and the dispatch, closing a time-of-check/time-of-use gap
(A7, Property 5a); (2) **effect-identity reconciliation** — the executor and the
verifier reconcile the external effect's target/payload against the signed grant, so a
key hit with different content is never reported `COMMITTED` (B3, E4, Property 5b/5d,
verifier invariant `effect-content-mismatch`); (3) **atomic nonce + claim** — folded
into one transaction so a hard exit can't strand an `AVAILABLE` attempt with a consumed
nonce (C5, Property 5c, verifier invariant `no_consumed_nonce_with_available_attempt`).

### Review round 4 (exact-head review 6202502011) — closed here

Each finding was first reproduced against the previous head, then fixed with a
regression that fails on that head:

1. **Verified-grant snapshot.** The executor re-read the caller-owned envelope after
   verifying it, so an envelope whose payload changed between reads could dispatch to an
   unverified target. The envelope is now read once into a plain snapshot; only that
   snapshot is verified, and execution uses the frozen verified `Grant` it yields. The
   claim also requires the grant's identity (action digest, target, allowance) to equal
   the registered authority row and records the winning envelope (A8, A9, Property 6a).
2. **Receipt semantics.** The verifier validated receipt content only for `COMMITTED`
   receipts and only signature-checked stored grants. It now binds every stored grant's
   signed identity to its ledger row (`grant_identity_bound_to_ledger`), reconciles
   **every** signed receipt — identity, signed-grant fields, ledger verdict and external
   effect state — whatever its verdict (`every_receipt_consistent_with_ledger_and_grant`),
   and requires a receipt for every `COMMITTED` verdict (`every_committed_verdict_has_receipt`)
   (E5–E7, Property 6e/6f).
3. **Execution/recovery overlap.** Recovery could close a live `DISPATCH_AUTHORIZED`
   attempt as `KNOWN_NOT_DISPATCHED` before the provider committed; a lost response then
   left a real effect mislabeled and unrecoverable. Dispatch and recovery are now fenced
   by a per-attempt lock, and every state transition is compare-and-swap (C6, C7,
   Property 6c/6d) — see *Execution/recovery fencing* below.
4. **Contention coverage.** Distinct signed nonces sharing one attempt now isolate the
   claim CAS (B4, Property 6b), kept separate from same-grant/same-nonce replay
   contention (B1). The CAS already behaved correctly; this closes a coverage gap.

The three invariants added in this round are also iterated by Property 4; they are added
checks over the same estate, not new independently varied scenarios.

## The two-store transaction & idempotency boundary

There is **no distributed transaction** here, by design — you cannot two-phase-commit
with a real external API. Correctness comes from two separate durable stores and a
strict ordering, not from a global lock (a per-attempt dispatch lock fences recovery
— see *Execution/recovery fencing*).

- **Authority ledger** (`authority.db`, SQLite, WAL + `synchronous=FULL`) — the
  governance record. A single-use attempt advances
  `AVAILABLE → CLAIMED → DISPATCH_AUTHORIZED → CLOSED`. The claim is an **atomic
  compare-and-swap** — `UPDATE authority SET state='CLAIMED' WHERE attempt_id=? AND
  state='AVAILABLE'` — and `rowcount == 1` means *this* caller won. SQLite serialises
  writers, so under concurrency exactly one claimer proceeds.
- **External world** (`world.db`, separate SQLite) — models the external service's
  **own** idempotency: `UNIQUE(idempotency_key)` makes the effect **at-most-once** per
  key. A duplicate key performs no second effect.

The ordering is what makes a crash at any instruction recoverable:

1. **Independently** verify the grant (ed25519 signature, expiry,
   `action_digest == sha256(canonical(action))`).
2. Atomically **claim** (durable). Losers never dispatch.
3. Durably record **`DISPATCH_AUTHORIZED` before** touching the external world.
4. Perform the **idempotent** external effect.
5. Bind a signed **receipt** to the real effect, then close.

**Recovery reads the external world; it never guesses.** A claimed/authorized attempt
with no effect → `KNOWN_NOT_DISPATCHED` (consumption retained, **no resend**). With an
effect → `COMMITTED`, receipt bound to the real effect. An uncertain outcome is never
promoted to success without a confirmed external effect, and recovery never creates a
second effect. This is the transactional-outbox / idempotency-key pattern, made
explicit and tested, not a two-phase commit.

### Execution/recovery fencing

Absence of an effect is only evidence of "not dispatched" if no live dispatcher can
still commit one. Each attempt therefore has a **dispatch lock** — an exclusive SQLite
lock on a small per-attempt file next to the ledger. `execute()` holds it from claim to
close; `recover()` only resolves an attempt while holding it and **skips** any attempt a
live executor holds, so that attempt stays recoverable instead of being guessed closed.
The OS releases the lock when a process dies, so a crashed executor never blocks
recovery. As defense in depth, `CLAIMED → DISPATCH_AUTHORIZED` and every terminal
transition are compare-and-swap: an attempt closed out of band is never dispatched.

Limits, stated plainly: a provider call that **hangs** keeps *its* attempt locked
(recovery skips that attempt until the call returns or the process exits) but blocks no
other attempt; and file locks are **host-local**, so this fences executors and recovery
on one host only. Multi-host deployment needs a distributed lease with fencing tokens.

## Threat model (the explicit assumptions)

The adversary **may**: replay, alter, or expire grants; race N attempts concurrently;
and crash the process at any instruction. The adversary **may not**: forge the
authorizer's ed25519 signature, or bypass the external store's unique constraint
(i.e. the external service honours its idempotency key). Executors and recovery share
one host (the dispatch lock is a host-local file lock), and a provider failure reported
*before* commit is taken to mean no late commit will follow. The properties are asserted
**only under these assumptions.** Change the assumptions and the claims must be
re-derived.

## What this does — and does not — establish

- **Does:** demonstrate, reproducibly, that the modelled chain upholds the six
  properties under the stated threat model, with durable state and external
  idempotency, on any machine in under a second.
- **Does not:** establish anything about a deployed system. The production a11oy
  authorization boundary is `IMPLEMENTED NOT DEPLOYED` (105 receipted policy assertions
  pass; it is not wired to the served path). Here, SQLite stands in for both the
  production durable store and the external service's idempotency. Real networks,
  real partial failures, real clock skew, and a real external API's idempotency
  semantics are **out of scope** and must be qualified separately.

## From reference implementation to a deployed guarantee

1. Port the executor onto the real runtime and a real external service's idempotency
   keys. The `ExternalWorld` class is the single seam.
2. Measure cost and reliability; add fault injection in CI.
3. Compare honestly with prior art — sagas, the transactional outbox, idempotency
   keys, two-phase commit — and state precisely what is and isn't new.
4. Have an **independent team** reproduce it against their own external target.

Until those are done, this is a tested reference implementation — nothing more, and
nothing dressed up as more.

*Readiness is not evidence. Control before action; evidence after.*
