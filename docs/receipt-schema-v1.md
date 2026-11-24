# Model Receipt Schema v1 (szl.receipt.model/v1)

Canonical, machine-verifiable receipt binding a SZLHOLDINGS HF model to its GitHub source of truth, eval evidence, and the TRUE identity of the backend that produced or measured it. Authored by the obl17 council lane (Kimi governing, Mistral + GPT-6.2-sol convergent) from the 2026-11-22/23 council ruling and the first-ever HF model-receipts census (419 models: 407 with receipt-like files at filename-pattern level, 171 rich, 12 with none; 411 referencing github.com/szl-holdings source).

## Fields
- schema: exactly szl.receipt.model/v1
- receipt_id: stable identifier (urn:szl:receipt:... recommended)
- model_id: HF repo id (e.g. SZLHOLDINGS/<name>)
- artifacts: [{path, sha256}] - weights/config file paths with lowercase hex sha256 (64 hex)
- source_of_truth: {github_repo, commit} - GitHub is the source of truth; commit MUST be a full 40-hex sha, never a branch or tag name
- eval: [{dataset, revision, split?, metric, value, baseline?, repro_command}] - at least one measured row with a reproduction command
- runtime: {backend_true_identity (REQUIRED), declared_backend?, hardware?, harness_version?} - the measured true identity of the serving/producing backend
- provenance: {license (REQUIRED), training_lineage?, base_model?}
- generated_at: ISO-8601 UTC ending in Z
- generator: which tool/rail produced this receipt

## Rail-honesty rule (hard failure)
Measured 2026-11-23 via ollama /api/tags remote metadata: the community rails treyleo16/claude-opus-5-5, treyleo16/gpt-6-1-sol, and treyleo16/gpt-6-astra all resolve to ONE shared remote backend gemma4:31b at ollama.com. If a receipt declares one of these rails as declared_backend, backend_true_identity MUST be the measured shared backend (gemma4:31b). Any attempt to present an aliased rail as a distinct model identity is rejected with a RAIL-ALIASING VIOLATION. Genuine cloud rails (kimi-k3.1-pro, mistral-large-4, glm-5.3) record their own identities.

The rule covers both the bare rail name and its explicit Ollama default tag, `:latest`. Other version tags require their own backend measurement. A passing receipt validates the declared binding. It supplies no independent council vote.

## Validation
Pure-stdlib validator: szl_receipt.schema_v1 (validate() returns error list; validate_or_raise() raises SchemaError). Tests: tests/test_schema_v1.py (valid receipt passes; missing fields fail; bad sha256 fails; branch-name-as-commit fails; aliased rail honest passes; aliased rail disguised identity rejected).

## Census calibration note
The owner has stated 3 of the HF models are fully receipted today. Those 3 receipts should be expressed in this schema to calibrate the census checker; models with zero receipt-like files (12 measured) are the first closure targets.
