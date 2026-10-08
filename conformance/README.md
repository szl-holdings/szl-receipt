# Receipt conformance and cross-verifier benchmark

## Release-manifest byte gates

Run from the repository root:

```sh
python conformance/run_vectors.py --vectors conformance/vectors/ --receipt release/run-manifest.json --require-all-pass
```

The runner is standard-library only. It loads the repository's production
`src/szl_receipt/_canonical.py` directly without initializing the package or its
crypto dependencies. A source checkout containing that module is required.

Five implemented gates:

- V01: JSON canonicalization stability.
- V02: exact DSSE PAE worked vector, literal `DSSEv1` prefix, then two
  ASCII-decimal byte-length-prefixed fields (type and decoded payload).
- V03: minimal-DER signature parsing.
- V04: predecessor-hash linkage, when predecessor bytes are supplied.
- V05: timestamp monotonicity, when a predecessor is supplied.

`--require-all-pass` exits 1 when any check disagrees with its expected result.
These gates do not establish signature validity, signer trust, model quality,
runtime readiness, or release authorization.

### Fixed PAE vectors and regression

[The DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
defines:

```text
DSSEv1 SP LEN(type) SP type SP LEN(body) SP body
```

The external worked example and original SAMPLE empty/Unicode/binary vectors
are frozen in [pae_byte_vectors.json](pae_byte_vectors.json). Both release and
production encoders must match those exact bytes.

The earlier release runner incorrectly emitted a length-prefixed context:
`6 DSSEv1 ...`. Its self-check accepted that nonstandard encoding. V02 now
uses the unchanged production encoder and checks the external worked example
before parsing the manifest. The old encoding, binary length prefixes, wrong
fields and trailing bytes are negative controls.

Run the byte tests without installed dependencies:

```sh
python -S -m unittest tests.test_release_pae_conformance -v
```

## Exact-byte signature and fixture-policy benchmark

Install the repository's declared development dependencies in your chosen
environment:

```sh
python -m pip install -e ".[dev]"
```

Run a strict comparison with an explicit local receipt:

```sh
python conformance/benchmark_verifiers.py --require-openssl --output verifier-benchmark.json
```

The script discovers OpenSSL on PATH, or Git for Windows' bundled executable.
You can select the executable explicitly:

```powershell
python .\conformance\benchmark_verifiers.py --openssl 'C:/Program Files/Git/usr/bin/openssl.exe' --require-openssl --output verifier-benchmark.json
```

Omit `--output` to print the result without writing a receipt file. No implicit
parent directory is created. The printed receipt digest binds the exact saved
UTF-8 bytes. A missing or incomplete required OpenSSL comparison exits 2 as
UNAVAILABLE; an unexpected verdict exits 1 as BLOCKED.

### Twelve frozen-per-run SAMPLE cases

| Case | Raw signature | SZL receipt profile | Local fixture gate |
|---|---|---|---|
| Valid | Accept | Accept | Admit within SAMPLE policy |
| Payload/type/signature tamper (three cases) | Reject | Reject | Deny |
| Wrong verification key | Reject | Reject | Deny |
| Pretty JSON, original signature | Reject | Reject | Deny |
| Pretty JSON, freshly re-signed | Accept | Reject canonical profile | Deny |
| Advisory digest altered | Accept | Reject digest binding | Deny |
| Unsigned | Reject | Reject unsigned-honest | Deny |
| Correctly signed wrong artifact | Accept | Accept | Deny artifact byte binding |
| Second valid signer outside fixture set | Accept | Accept | Deny fixture signer policy |
| Correctly signed wrong expected source | Accept | Accept | Deny source policy |

Raw cryptography and OpenSSL verify the same exact decoded-payload production
PAE bytes. The SZL receipt verifier additionally checks its canonical receipt
profile and advisory digest. Artifact, source and signer checks are separate
local policy comparisons; their inputs are authenticated only by the combined
signature/profile gate. Envelope `keyid` is a hint and grants no authority.

The receipt records public fixture envelopes and public keys, target artifact
bytes/hash, a frozen policy/hash, expected and actual stage verdicts, source
file/function hashes, dependency/backend versions, actual OpenSSL commands and
bounded outputs. Private fixture keys exist only in memory and are not
serialized. OpenSSL receives public key/signature files and PAE bytes on stdin;
its temporary directory is removed. No network, provider, model, agent tool, untrusted
layout inspection, or production effect is invoked.

Inputs are SAMPLE; observed local check results are MEASURED. The fixture
source label is compared with a frozen expectation and does not prove source
correctness. Keys remain REPO_DECLARED; production authorization is BLOCKED;
independent external replay is NOT RUN. Adapter diversity does not establish
implementation independence, general DSSE/cosign conformance or a SLSA level.

Primary references: [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md),
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md),
[SLSA artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts).

## CI and replay

Primary CI runs the strict benchmark after the package tests and retains its
public SAMPLE receipt for each Python matrix version. Missing required external
verification or any verdict mismatch fails the job.

```sh
pytest -q tests/test_release_pae_conformance.py tests/test_verifier_benchmark.py
```

The report carries the actual working-tree source hashes and clean-state
observation. A local report made before commit is not a committed-source release
receipt; exact-head CI and normal protected merge remain separate gates.
