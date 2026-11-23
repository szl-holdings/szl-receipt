# SPDX-License-Identifier: Apache-2.0
# Receipt evidence service — schema, runbook, and the 3 -> 418 scale-out

This document specifies the typed evidence layer (`szl_receipt.evidence`)
and the read-only HTTP service + viewer that make model receipts — and
their limitations — inspectable.

## Doctrine

- **Assertion never renders as verification.** Every claim carries one
  status from the closed enum `MEASURED | REPRODUCED | SELF_ASSERTED |
  MISSING`. Only the first two count toward coverage.
- **Missing is data.** A `MISSING` claim must name its gap; the service
  and viewer render gaps as gaps — never as zero, "passed", or hidden.
- **The denominator is explicit.** Every coverage stat reports the count
  and the total it was computed over. N generated cards are never
  conflated with N verified models.
- **Fail-closed loading.** An evidence directory that violates the
  contract aborts the loader with the offending file named. There is no
  partial-load mode.
- **Admission is not evaluation.** The `publication` slot is recorded
  like any other evidence; it never acts as an umbrella verdict.

## Claim schema

One claim object per evidence statement:

| field | required for | rules |
|---|---|---|
| `claim_id` | all | lowercase slug `<= 128` chars from `[a-z0-9-_/]`, unique per model |
| `slot` | all | one of `identity, dataset, evaluation, environment, safety, publication` |
| `status` | all | the closed enum above |
| `summary` | none | one line a reviewer can read |
| `evidence_uri` | `MEASURED`, `REPRODUCED` | resolvable URI to the artifact (CI run, signed receipt envelope, HF artifact) |
| `artifact_digest` | `MEASURED`, `REPRODUCED` | lowercase 64-char hex sha256 of the evidence artifact |
| `evaluated_at` | `MEASURED`, `REPRODUCED` | RFC3339 UTC (`Z` only; naive or non-zero offsets are rejected) |
| `evaluator` | `MEASURED`, `REPRODUCED` | evaluating identity (person, service, workflow) |
| `max_age_days` | optional | positive integer freshness horizon; exceeding it surfaces the claim as `stale` in the ledger without changing its status |
| `named_gap` | `MISSING` | what is absent, in words |
| `notes` | none | context; never evidence |

A model record is `{"model_id", "revision", "claims": [...]}`. Duplicate
`claim_id`s inside one record are a load-time contradiction failure.

## Classification

- `fully_evidenced`: all six slots have at least one verified claim.
- `partially_evidenced`: at least one, not all.
- `inventory_only`: no verified claims at all.

## Service

Stdlib-only. Run it against any evidence directory:

```
python -m szl_receipt.evidence.service \
  --evidence-dir receipts/evidence \
  --viewer-dir examples/evidence-viewer \
  --port 8787
```

Routes (all read-only, JSON, `Access-Control-Allow-Origin: *`):

| route | returns |
|---|---|
| `GET /api/models` | list with classifications + denominator |
| `GET /api/models/{id}` | full record: slots, claims, named gaps |
| `GET /api/models/{id}/evidence` | verified claims only + `excluded_gaps` so an empty list never looks like completeness |
| `GET /api/coverage` | ledger: classifications, per-slot status counts, negative evidence (optional `?as_of=RFC3339Z` for staleness) |
| `GET /api/compare?ids=a,b` | side-by-side slot matrix; unknown ids are named, not guessed |

The bundled viewer (`examples/evidence-viewer/index.html`) consumes the
JSON with zero dependencies; it works from the same origin, or from a
static host (GitHub Pages, HF Space static build) via `?api=<service-url>`.

## Scale-out: 3 -> 418

1. **Freeze the schema on the goldens.** The three golden
   fully-evidenced cards define the contract; do not extend the schema
   per model.
2. **Inventory first.** Emit one record per known model (claims can be
   empty — `inventory_only` is a valid, honest state) to make the
   denominator real. Validate all 418 inventories.
3. **Auto-discover what already exists.** Harvest machine-checkable
   evidence from CI artifacts, gate records, and signed receipts; convert
   only what a validator can verify (digests, timestamps, evaluators).
4. **Rank the rest** by external traffic / release importance times
   evidence gap, and fully evidence the highest-impact decile first.
   Every remaining model keeps its named gaps visible in the ledger.
5. **Track, never conflate**: `fully_evidenced / partially_evidenced /
   inventory_only` per model, reported with the denominator, in every
   exported stat.

A model becomes "done" when all *available* evidence resolves and every
missing item has a named gap — not when every field is populated.
