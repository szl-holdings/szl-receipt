# SZL Receipt Wire — Rust/Python differential proving ground

**State: SOURCE-ONLY / REVIEW-REQUIRED / NOT A RELEASE.**

This small Rust library and separate optional PyO3 wheel implement only the **DSSE v1 pre-authentication encoding (PAE)** byte format. Python source at src/szl_receipt/_canonical.py remains authoritative and unchanged. The existing szl-receipt-dsse PyPI distribution, signature implementation, DSSE policy, and release approval paths remain unchanged.

Protocol: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
Python binding: https://github.com/PyO3/pyo3
Wheel builder: https://github.com/PyO3/maturin
Verified Rust compiler selection: rust-toolchain.toml (1.91.1).

## Local source verification (from repository root)

    cargo fmt --manifest-path rust/szl-receipt-wire/Cargo.toml --all -- --check
    cargo test --locked --manifest-path rust/szl-receipt-wire/Cargo.toml
    cargo clippy --locked --manifest-path rust/szl-receipt-wire/Cargo.toml --all-targets -- -D warnings
    cargo build --locked --manifest-path rust/szl-receipt-wire/Cargo.toml --bin szl-receipt-wire-cli
    python3 conformance/rust_wire_conformance.py --binary rust/szl-receipt-wire/target/debug/szl-receipt-wire-cli

The differential runner checks all four committed original Python DSSE PAE byte vectors (official, empty, Unicode and binary), plus three malformed-input refusals. It records both source hashes, not an approval or a cryptographic signature.

## Separate, unpublished Python wheel

    cd rust/szl-receipt-wire
    maturin build --locked

The resulting separate experimental szl-receipt-wire distribution exposes the Python module szl_receipt_wire, with the byte-only pae(payload_type, bytes_payload) entrypoint. No auto-import or silent Rust fallback is added to existing Python package consumers. A wheel build does not authorize PyPI publication or runtime use.

Security gate: the optional PyO3 binding is pinned by Cargo.lock to PyO3 0.30.1. This version is outside the affected ranges of RUSTSEC-2026-0176 and RUSTSEC-2026-0177 (patched in 0.29.0). Trivy's HIGH/CRITICAL gate is not suppressed. No cryptographic verification is claimed.

The Rust implementation imposes **local** 16 MiB payload and 4096-byte type caps; these are not restrictions in the DSSE specification, and the Python canonical implementation accepts larger inputs. The CLI exposes arguments to the process list: use only the supplied public SAMPLE fixtures, never credentials or private receipts.

## Explicit non-claims

- No ECDSA P-256 or Ed25519 signature verification; no trusted key, certificate, signer identity, freshness, model evaluation, deployment, or release determination.
- No Lean theorem or Kani/Verus proof for this crate.
- No Hugging Face kernel upload, Cloudflare Worker deployment, or PyPI publishing.
- No claim that a green sample means the whole 176+ repository estate is Rust-converted.
- No change to authority: missing signing keys, SOURCE_AHEAD, publisher drift, expired evidence, and maintenance holds remain HOLD.
