# Pre-registered measurement plan

Registered **before** any reliability or savings claim, so results cannot be chosen
after the fact. This plan concerns the accountable-execution guarantee; it does not
authorize any paid run, deployment, or model-status change. Numbers are filled in
only after the runs described here execute under the stated conditions.

## 1. Question

Does placing an independent, fail-closed authorization boundary + durable idempotent
executor + independent verifier in front of an agent's actions **reduce unauthorized
and duplicated effects to zero under an explicit threat model**, and at **what cost**
in latency, throughput, and engineering, relative to simpler alternatives?

## 2. Arms (compared under matched conditions)

1. **Unguarded** — the model proposal executes directly (no boundary). Baseline for
   unauthorized/duplicate effects and for raw latency.
2. **Simple boundary** — a deterministic allowlist + a single idempotency key, no
   receipts, no independent verifier.
3. **This reference implementation** — grant/claim/idempotent-effect/receipt/verifier
   (the code in this directory).
4. **SZL stack + proposed additions** — the deployed a11oy/Hatun path once wired
   (currently `IMPLEMENTED NOT DEPLOYED`); measured separately and never conflated
   with arms 1–3.

## 3. Task distribution (pre-registered)

- A fixed mix of authorized actions, each with a known-correct expected effect.
- Adversarial injections at a fixed rate: wrong-digest, expired, replayed, wrong-tenant,
  missing-authority, forged-signature, concurrent duplicates, and provider faults.
- Concurrency levels: 1, 8, 32, 128 simultaneous attempts.
- Crash schedule: process kill at each injection point in the matrix (A–F), fixed seed.
Safety negative controls are scored **separately** from useful-task completion.

## 4. Threat / failure model (the assumptions results are valid under)

Adversary may replay/alter/expire grants, race attempts, crash the process at any
instruction, and make the provider time out / return 5xx / lose a response. Adversary
may **not** forge the authorizer's signature or bypass the external service's
idempotency key. A timeout is **not** treated as proof of cancellation or of no effect.

## 5. Metrics (primary → safety; secondary → cost)

Primary (must be zero / exact):
- unauthorized-effect rate (effects from a denied/absent authority) — target **0**.
- duplicate-effect rate (more than one effect per attempt) — target **0**.
- false-success rate (a COMMITTED claim with no confirmed external effect) — target **0**.
- uncertainty-preservation: fraction of ambiguous outcomes resolved by readback, not
  by guessing — target **100%**.

Secondary (cost, reported with variance and hardware):
- false-deny rate on authorized actions (availability cost of fail-closed).
- added latency per action (p50/p95/p99) and throughput vs each arm.
- recovery time after crash; verification time for an independent party.
- engineering cost (lines, dependencies, operational surface).

## 6. Evidence labels (orthogonal; never collapsed to "done")

`METADATA_ONLY · SOURCE_REVIEWED · TESTS_REPORTED · TESTS_REPRODUCED · RUNTIME_VERIFIED
· NOT_RUN · BLOCKED · UNKNOWN`. This reference implementation is **TESTS_REPRODUCED**
(49 checks, 22 unittests and 30 matrix rows as separate suites, rerun here). A deployed claim requires
**RUNTIME_VERIFIED** against a real external-state oracle — explicitly out of scope here.

## 7. Matched conditions

Same workload, provider semantics, model revisions, hardware, and concurrency across
arms. Fixed seeds. Each number carries its source head, command, environment, and raw
output. No figure is added across categories (e.g. tests + subtests are never summed).

## 8. Stopping / falsification

The thesis is **falsified** if any arm-3 run shows a nonzero unauthorized-, duplicate-,
or false-success rate under the stated assumptions, or if the fail-closed cost
(false-deny or latency) is worse than arm 2 without a corresponding safety gain. Report
failing cases and superseded claims; do not drop them.

## 9. Prior work (reused, not reinvented — state what is actually new)

- **Transactional outbox / idempotency keys** (Stripe-style): arms 2–3 use exactly
  this for external at-most-once. Not novel.
- **Sagas / compensations**: an alternative to the durable-intent + readback pattern;
  compared, not used.
- **Two-phase commit**: rejected — you cannot 2PC a real external API; hence
  durable-intent-before-call + reconcile-by-readback.
- **Policy engines** (XACML, OPA/Rego) and **supply-chain attestation** (in-toto,
  DSSE, SLSA): the grant/receipt layer is in this family.
- **Candidate novelty to test, not assert:** the *composition* — an independent,
  signature-bound grant checked at the effect boundary, + idempotent effect, +
  signed receipt, + an independent verifier that detects a *lying executor* — as one
  reproducible, honest-by-construction guarantee. Whether that composition is more
  than the sum of its known parts is exactly what arms 1–4 are designed to measure.

*Readiness is not evidence. This plan is registered before results exist.*
