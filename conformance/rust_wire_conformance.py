#!/usr/bin/env python3
"""Offline differential PAE parity: frozen DSSE vectors versus Python and Rust.

This compares only pre-authentication-encoding bytes. No signature is verified,
no authorization is granted, and no model or provider is contacted.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


def read_python_pae(root: Path):
    path = root / "src/szl_receipt/_canonical.py"
    spec = importlib.util.spec_from_file_location("szl_receipt_canonical_source", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("canonical Python module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.pae


def invoke(binary: Path, payload_type: str, payload_hex: str):
    return subprocess.run(
        [str(binary), "pae-hex", payload_type, payload_hex],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
        shell=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    binary = args.binary.resolve()
    if not binary.is_file():
        print("UNAVAILABLE: Native Rust test binary not built", file=sys.stderr)
        return 2

    canonical_pae = read_python_pae(root)
    fixture = root / "conformance/pae_byte_vectors.json"
    raw = fixture.read_bytes()
    vectors = json.loads(raw)
    if vectors.get("schema") != "szl.pae-byte-vectors/v1":
        raise RuntimeError("unexpected vector schema")
    items = vectors.get("vectors")
    if not isinstance(items, list) or len(items) != 4:
        raise RuntimeError("incomplete frozen DSSE test corpus")
    if len({row.get("id") for row in items}) != len(items):
        raise RuntimeError("duplicate frozen fixture ID")
    matched = 0
    for row in items:
        payload_type = row["payload_type"]
        payload_hex = row["payload_hex"]
        expected = bytes.fromhex(row["expected_pae_hex"])
        assert canonical_pae(payload_type, bytes.fromhex(payload_hex)) == expected, row["id"]
        actual = invoke(binary, payload_type, payload_hex)
        assert actual.returncode == 0, (row["id"], actual.returncode)
        assert actual.stdout.strip() == expected.hex(), row["id"]
        matched += 1
    for kind, hex_body in (("", "aa"), ("application/x-test", "f"), ("application/x-test", "zz")):
        invalid = invoke(binary, kind, hex_body)
        assert invalid.returncode == 2, (kind, invalid.returncode)
        assert not invalid.stdout.strip(), "invalid requests must not return PAE"
    source = root / "rust/szl-receipt-wire/src/lib.rs"
    print(json.dumps({
        "schema": "szl.rust-wire-parity/v1",
        "state": "PASS_SOURCE_ONLY",
        "reference_vectors": matched,
        "negative_controls": 3,
        "python_reference_sha256": hashlib.sha256(
            (root / "src/szl_receipt/_canonical.py").read_bytes()).hexdigest(),
        "rust_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "vectors_sha256": hashlib.sha256(raw).hexdigest(),
        "cryptographic_signature_verified": False,
        "release_authorized": False,
        "provider_effects": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, KeyError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"BLOCKED: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
