# Accountable AI Execution — tested reference implementation

A self-contained reference implementation of the governed-action chain, with a test
suite that exercises its four properties under adversaries. It is **a tested
reference implementation under explicit assumptions — not a proof about any deployed
system, and not an unconditional guarantee.**

```
python3 prove.py                       # property suite (happy path + adversaries)
python3 -m unittest test_negative -v   # independent negative/adversarial tests
python3 acceptance_matrix.py           # A–F acceptance matrix (18 named rows)
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

`test_negative.py` runs the adversarial cases (1, 3, 4) as standalone `unittest`
cases, independent of the `prove.py` harness, so the negative controls can be run and
reviewed on their own.

## The A–F acceptance matrix

`acceptance_matrix.py` runs **18 named, individually-labelled rows** grouped into six
families, each asserting the exact behaviour that must hold (and the things that must
*not* happen). `--json` writes the machine-readable outcomes to `DEMO_CASES.json`.

| Family | Rows | What it pins down |
|---|---|---|
| **A. Authority is exact & single-use** | A1–A6 | tampered-body, expired, missing-authority, wrong-tenant, replay, forged-signature → **zero** effect |
| **B. Concurrency** | B1–B2 | N racers → at-most-one effect and **truthful losers**; same key / different payload → no second effect |
| **C. Crash safety** | C1–C4 | hard death at four points never turns an uncertain result into a success claim |
| **D. Provider faults** | D1–D2 | fault **before** commit → `UNKNOWN`, not-dispatched; commit **but response lost** → `UNKNOWN`, then `COMMITTED` by readback |
| **E. Verifier catches a liar** | E1–E3 | forged effect, tampered receipt, executor that *claims* success with no effect → **detected** |
| **F. Positive path** | F1 | authorized action → exactly one real effect, correct binding, all invariants clean |

The D family is the honesty core: a provider timeout or lost response is **never**
read as proof of cancellation or of success — the outcome stays `UNKNOWN` until the
external world is read back. Nothing is summed across families; each row stands alone.

## The two-store transaction & idempotency boundary

There is **no distributed transaction** here, by design — you cannot two-phase-commit
with a real external API. Correctness comes from two separate durable stores and a
strict ordering, not from a global lock.

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

## Threat model (the explicit assumptions)

The adversary **may**: replay, alter, or expire grants; race N attempts concurrently;
and crash the process at any instruction. The adversary **may not**: forge the
authorizer's ed25519 signature, or bypass the external store's unique constraint
(i.e. the external service honours its idempotency key). The properties are asserted
**only under these assumptions.** Change the assumptions and the claims must be
re-derived.

## What this does — and does not — establish

- **Does:** demonstrate, reproducibly, that the modelled chain upholds the four
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
