# SZL Rust Frontier: source-first, evidence-bound adoption plan (2026-11-19)

**Scope**: execution plan, not a production release or a claim that every estate repository has been ported. GitHub protected main remains authoritative for each repo. All runtime and publication holds remain operative.

## Global leaders and primary-source evidence

| Project | Engineering pattern | Primary source | SZL applicability |
| --- | --- | --- | --- |
| Cedar / cedar-spec | Lean formal model + Rust policy evaluator + differential randomized testing, not blind trust in either implementation | https://github.com/cedar-policy/cedar-spec and https://arxiv.org/abs/2407.01688 | Formalize selected Hatun policy and refute implementations with generated counterexamples; never accept a Rust policy as approved merely because it compiles. |
| DSSE / in-toto / Sigstore | Stable signed-envelope PAE bytes, attested subject identity and signed transparency evidence | https://github.com/secure-systems-lab/dsse/blob/master/protocol.md and https://github.com/sigstore/sigstore-rust | Start with the frozen SZL DSSE byte vectors. A later Rust verifier must validate signer trust policies using maintained cryptographic libraries, never hand-roll signing arithmetic. |
| PyO3 / maturin | Rust implementations distributed as Python-native wheels | https://github.com/PyO3/pyo3 and https://github.com/PyO3/maturin | Python controls remain primary; native code is a pinned, opt-in extension only after tests and wheel review. |
| Hugging Face Safetensors | Rust-backed safe model-weight serialization and cross-language integration | https://github.com/huggingface/safetensors | Validate immutable model artifacts; do not confuse serialization safety with model quality, safe behavior, or release approval. |
| Apache DataFusion / Qdrant | Rust-based Arrow analytics and vector retrieval with metadata filtering | https://github.com/apache/datafusion and https://github.com/qdrant/qdrant | Evaluate a Rust query/retrieval backend for szl-lake and szl-retrieval-bench on pinned corpora and fixed qrels; measure recall as well as speed. |
| Cloudflare workers-rs | Rust compiled to WebAssembly with Workers platform bindings | https://github.com/cloudflare/workers-rs and https://developers.cloudflare.com/workers/languages/rust/ | Potential future receipt metadata verification at the edge; no deployed worker or permission to bypass Hatun or Cloudflare Access. |
| Kani / Verus | Bounded model checking and deductive verification of Rust | https://model-checking.github.io/kani/ and https://github.com/verus-lang/verus | Add formal harnesses to Rust admission logic only after a stable typed specification and negative test suite exist. |

Research references are prior art, **not partner endorsements or external code copied into SZL**. Review licenses and dependency SBOMs before accepting any external implementation.

## Cohorts and ownership

1. **Wire and provenance (szl-receipt, szl-lake)**. The first experimental Rust crate encodes DSSE PAE bytes with a strict Python differential suite. Next candidate: signed envelope verification using an audited library, public keys, exact source revision, and independently witnessed negative cases. Fail closed on missing proof; never treat unsigned as verified. Owner: canonical szl-receipt maintainer and guarded release lane.
2. **Governed agent calls (hatun-mcp, a11oy, szl-router)**. Keep Python SDK, policy schema and live routing untouched. Build a *shadow*, non-authoritative Rust evaluator only after the current action policy is extracted and frozen. Compare all policy verdicts, including deny/unknown/stale and approvals, against existing Python. Require formal specification and reviewer consent before promotion. Owners: Hatun canonical gateway and A11oy release lane.
3. **Math and proof (lutar-lean, szl-formulas, szl-invariants, szl-papers)**. Lean stays theorem authority. Investigate formally specified Rust helpers for finite arithmetic/receipt algebra, with Kani or Verus proofs for narrow properties and fresh Lean check on the actual target. Never upgrade Lambda uniqueness or conjectures by runtime hash claims. Owner: Lean research lane.
4. **Data and memory (szl-lake, szl-retrieval-bench, Second Brain)**. Benchmark DataFusion/Polars/Qdrant/Lance-inspired candidate backends against Python baseline with pinned document snapshots, rights, tenant isolation, retrieval qrels, MRR/nDCG/Recall, and contradiction/temporal tests. A fast result that loses evidence or recall fails. Owner: data and retrieval lanes.
5. **GPU and model artifacts (szl-gpu-bridge, szl-router, Hugging Face)**. Preserve Python/PyTorch/CUDA/Triton serving. Rust may accelerate tokenization, input validation and checksums; no GPU training or promotion authority without actual measured hardware receipts, rights, budget, provenance and evaluation. Owner: qualified compute lane.
6. **Edge and distribution (a-11-oy.com, a11oy.net, Cloudflare, PyPI)**. Future independent Rust/Wasm verifier must be reviewed and exercised in a separate Cloudflare preview under the correct account and access gates. The separate Maturin wheel must pass Linux/Windows/macOS compatibility, SBOM, release-hash and signed PyPI Trusted Publishing checks. Never publish through this source-only PR. Owner: Cloudflare and PyPI release lanes.

## Acceptance ladder

**A: SOURCE-ONLY** — bounded tests, pinned compiler and Cargo.lock, exact reference vectors, negative refusals, Python byte parity, no effect authority.

**B: REPRODUCIBLE REVIEW** — source PR with protected-main checks, security review, developer provenance and independent conformance, no release claims.

**C: INTEGRATION CANARY** — opt-in Rust extension against the original Python service, adversarial fuzz/property tests, no signer escalation, no silent fallback, p50/p95/p99 latency, CPU/memory, and source digest logged.

**D: PUBLISHER QUALIFICATION** — GitHub merge plus artifact bill of materials, signature and immutable revision; separately qualified HF model/kernel paths, Cloudflare edge preview, and PyPI Trusted Publishing, each with owner authority.

**E: OPERATIONAL RELEASE** — maintenance window approved, exact signed publisher/readback matched, live service tested, rollback tested; only then call a product fully operational.

**Non-negotiable:** CI success is not deployment. A Python/Rust parity receipt is a content proof, not a signature. Rust memory safety does not imply authorization correctness. Do not rewrite the whole estate without measured return on investment and formal preservation of critical invariants.
