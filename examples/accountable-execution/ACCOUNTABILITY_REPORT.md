# Accountability report — accountable-execution reference implementation

Maps this example to the briefed deliverables and acceptance cases, with an honest
status label on each line. Written so a reviewer can check every claim against an
immutable source and a rerunnable command, and can see exactly what is **not** covered.

**Scope.** This report concerns the code in `examples/accountable-execution/`. It is a
**tested reference implementation under the explicit threat model in `README.md`** — not
a claim about any deployed system, and not a blanket audit of the SZL estate. Where a
line refers to estate-wide work done elsewhere in the session, it is labelled as such and
not claimed as established by this PR.

## Evidence vocabulary (orthogonal labels; never collapsed to "done")

| Label | Meaning here |
|---|---|
| `TESTS_REPRODUCED` | Rerun in this repo on this machine; raw output in `RESULTS.txt`. |
| `SOURCE_REVIEWED` | A primary source was read at a pinned head; not re-executed here. |
| `TESTS_REPORTED` | A committed test/report was read; **not** rerun here. |
| `MODELED` | Represented in the reference, with a real seam to a deployed system. |
| `NOT_RUN` | Named and in scope, deliberately not executed. Stated, not hidden. |
| `BLOCKED` | Needs an approval / credential / ownership step that is not mine to take. |

`RUNTIME_VERIFIED` (observation against a real external provider) is **out of scope**
for this PR and appears nowhere below as achieved.

## Briefed deliverables (1–8)

| # | Deliverable | Status | Where / limitation |
|---|---|---|---|
| 1 | Per-asset inventory | `SOURCE_REVIEWED` (estate audit, elsewhere) | Done as session audit of the GitHub org + HF; **not** this PR's artifact. No `inventory.json` is claimed complete here. |
| 2 | One review card per asset | `SOURCE_REVIEWED` (partial, elsewhere) | Key assets reviewed at pinned heads in-session; a full per-asset card set is not part of this PR. |
| 3 | Consolidated resume / supersession | `SOURCE_REVIEWED` (partial, elsewhere) | Surviving lanes and holds tracked in-session; not re-asserted here. |
| 4 | Minimal reviewed diff + threat model + state machine + external-effect assumptions | `TESTS_REPRODUCED` | `gexec.py` (the chain), `README.md` (threat model, state machine, two-store boundary). A reference implementation in a new example dir — **not** a patch into the served runtime. |
| 5 | Reproducible local demo + separate verifier, durable state, adversarial, concurrency, crash injection | `TESTS_REPRODUCED` | `prove.py` (40 checks), `test_negative.py` (13 unittests), `acceptance_matrix.py` (22 rows), `independent_verify()` as the separate verifier. Durable SQLite stores; real subprocess hard-crashes; N-thread races. Round-3 review findings (action snapshot, effect-identity reconciliation, atomic nonce+claim) fixed and regression-covered. |
| 6 | Honest demonstration narrative + evidence package (claim → source → test → observation → limitation) | `TESTS_REPRODUCED` | This report + `README.md` + `RESULTS.txt`. No fabricated pass, signature, or live label; the chain is shown below. |
| 7 | Prior-work comparison + preregistered cost/reliability plan | comparison `SOURCE_REVIEWED`; cost eval `NOT_RUN` (pre-registered) | `MEASUREMENT_PLAN.md`. The comparison cites named prior art; the cost/reliability numbers are **registered before** any run, not reported. |
| 8 | Smallest remaining approval requests | enumerated below | Each names action, target, cost and stopping condition. None bundled. |

## Acceptance cases — briefed DEMO_CASES vs. what runs here

Each briefed case ⇒ the row(s) that exercise it, with an honest coverage label. "Zero
effects" is always asserted by an authoritative counter query (`world.count`), never by
silence. The briefed `status: NOT_RUN` markers are **replaced** only where a row actually
reproduces the behaviour.

| Briefed case | Covered by | Coverage |
|---|---|---|
| `deny-wrong-digest` | A1 | **COVERED** — reject, 0 effects |
| `deny-expired` | A2 | **COVERED** — reject, 0 effects. Clock-skew *window* sweep not run (see gaps). |
| `deny-replayed` | A5 | **COVERED** — second use denied, exactly 1 effect. Replay *after durable restart* is shown by the crash rows (C), not A5 itself. |
| `deny-bindings` | A3 (missing authority), A4 (wrong tenant), A6 (forged sig) | **COVERED** for these bindings; actor/policy-id and malformed-envelope bindings **NOT_RUN**. |
| `concurrent` | B1 | **COVERED** — 24 racers → exactly 1 effect, losers truthful. |
| `key-body-conflict` | B2, **B3** | **COVERED** — same key, different body → no second effect; existing key with a different target/payload → `EFFECT_CONFLICT`, never `COMMITTED` (reconciled in execute, recover, and verify). |
| `dedup-expiry` | — | **NOT_RUN** — provider dedup-retention expiry before retry is not modelled. |
| `crash-matrix` | C1–C5, D2 | **PARTIAL** — 5 crash points (incl. the atomic nonce+claim boundary, C5) + "provider commits before response" (D2). "During dispatch" and "response-before-local-commit" as distinct points are **NOT_RUN**. |
| `cancel-revoke-timeout` | D1 (provider timeout) | **PARTIAL** — timeout→UNKNOWN (never read as zero effects) is shown; explicit cancel/revoke and clock-skew races are **NOT_RUN**. |
| `lying-executor` | E3 | **COVERED** — signed COMMITTED with no effect is detected. "Claims one while provider has two" as a distinct over-effect scenario is **NOT_RUN**. |
| `tamper-evidence` | E1 (forged effect), E2 (tampered receipt), **E4** (effect content altered) | **COVERED** for effect, receipt, and post-commit effect-content tamper; policy/source-binding tamper **NOT_RUN**. |
| `positive-local` | F1 | **COVERED** — `TESTS_REPRODUCED, LOCAL_SIMULATED`: exactly 1 effect, verifier clean. |
| `positive-deployed` | — | **BLOCKED** — needs an approved real-provider operation; not my action. |

**Honest gaps (named, not hidden):** `dedup-expiry`; the full crash-matrix "during
dispatch" / "response-before-local-commit" points; `cancel-revoke-timeout` cancel+revoke
and clock-skew; "provider has two" over-effect; actor/policy-id and malformed-envelope
bindings; and all of `positive-deployed`. Zero observed failures in the covered rows is
**not** proof of zero risk — see `MEASUREMENT_PLAN.md` §8 (falsification).

## The evidence chain (claim → source → test → observation → limitation)

> **Claim.** A proposal only becomes an external effect if a signature-bound grant
> authorizes the **exact** action; at most one effect occurs per attempt even under
> concurrency and crashes; and an independent verifier can detect a lying executor.

- **Source.** `gexec.py` at this PR's head (the chain); `README.md` (threat model +
  two-store ordering). The production boundary it models is a11oy's policy runtime,
  `IMPLEMENTED NOT DEPLOYED` — committed report read (`TESTS_REPORTED`), not rerun, and
  not wired to the served path.
- **Test.** `python3 prove.py` (40), `python3 -m unittest test_negative -v` (13),
  `python3 acceptance_matrix.py` (22). Durable stores, real subprocess crashes, thread
  races.
- **Observation.** `RESULTS.txt` — exact commands and raw output, no secrets. Counts are
  reported per suite and **never summed** across suites (40, 13, and 22 are distinct
  experiments, not a "75").
- **Limitation.** SQLite stands in for both the durable store and the external service's
  idempotency. Real networks, real partial failure, real clock skew, and a real API's
  idempotency semantics are out of scope. Change the threat model and every claim must be
  re-derived.

## Deliverable 8 — smallest remaining approval requests (none bundled)

Each is a separate, stop-conditioned request. I have taken none of these.

1. **a11oy ownership/transfer** — target: the a11oy repo/runtime controller. Effect:
   permission change. Cost: none. Stop: once ownership is confirmed; no code change implied.
2. **Deployed acceptance (`positive-deployed`)** — target: one pinned real-provider
   operation. Effect: a single real external effect. Cost: provider-dependent; needs a
   declared ceiling. Stop: one observed case, `RUNTIME_VERIFIED` for that case only.
3. **Cost/reliability eval run (`MEASUREMENT_PLAN.md`)** — target: the four arms. Effect:
   compute/token spend. Cost: must be approved against a ceiling before any paid run. Stop:
   the pre-registered sample size.
4. **DOI / archival egress** — target: Zenodo (or equivalent). Effect: external publication.
   Cost: none/low. Stop: on mint; nothing auto-published.
5. **Rollout of the corrected domain gate to other repos** — target: the ~45 remaining
   repos. Effect: CI change across repos. Cost: none. Stop: after review of the gate's open
   findings resolves; not part of this PR.

*No monetary, energy, latency, or live-deployment claim appears above without an
authoritative measurement. Readiness is not evidence. Control before action; evidence after.*
