# szl-receipt domain leader study r1 (propose-only)

Date: 2026-11-24. Method: web-verified leader landscape + governing-seat ratification (Kimi nonce T12-RULING-20261124-K1). Study pinned to szl-receipt HEAD 489c048f3c779583ed19feda7ee1ad93841cb42e, fetched 2026-11-24. This card is documentation only; it changes no code, CI, config, or existing PR status. All absorb actions are FUTURE PROPOSALS (non-authorizing); implementation and merges remain separately reviewed and gated. L Conjecture 1: OPEN (advisory, never a closed theorem). No speedup, energy, or proven-trust claims; upstream performance claims are labeled as upstream claims only. No unverified signing, attestation, or provenance-level claims; this study verifies nothing about this repo's artifacts.

## Domain: Shared signed-receipt primitive for SZL components, centered on DSSE envelopes and ECDSA-P256 signing with cosign compatibility stated as a design goal, while keeping UNSIGNED-honest fallback visible and never weakening the signature wall.

## Leaders studied (web-verified 2026-11-24)
1. DSSE (https://github.com/secure-systems-lab/dsse) - moat: A small, explicit envelope and signature protocol that separates payload typing and encoding from signature production and verification.
2. Cosign (https://github.com/sigstore/cosign) - moat: A widely used Sigstore signing and verification tool with documented container-signature workflows and support for key-based and keyless modes.
3. in-toto (https://github.com/in-toto/in-toto) - moat: A supply-chain metadata framework whose attestations and layouts make declared steps, materials, products, and verification policy explicit.

## Absorb actions (FUTURE PROPOSALS, non-authorizing)
1. (DSSE) Propose a documentation-only design note comparing this library's receipt envelope terminology, payload-type handling, and unsigned fallback labels with DSSE concepts, without asserting protocol conformance or verification results. Cost: doc-only, approximately one maintainer review cycle; limit: note only, no code, no infra changes.
2. (Cosign) Propose a documentation-only review that maps cosign compatibility statements to explicit design-goal labels and records which interoperability questions would require later separately gated testing. Cost: doc-only, approximately one to two maintainer review cycles; limit: note only, no code, no infra changes.
3. (in-toto) Propose a documentation-only design note examining whether future receipt metadata could reference in-toto attestation concepts while preserving a clear boundary between unsigned receipts, signed receipts, and unverified provenance claims. Cost: doc-only, approximately one maintainer review cycle; limit: note only, no code, no infra changes.
4. Baseline preserve honestly: Preserve honest truth labels, keep UNSIGNED-honest fallback explicit and visible, describe signing compatibility only as a design goal unless separately verified, and never treat documentation as evidence of cryptographic assurance or permission to bypass the signature wall.

## Do not do (per governing seat)

Do not merge, bypass the signature wall, or claim implementation beyond this card.
