# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""
Canonical JSON serialisation and the DSSE Pre-Authentication Encoding.

``canonical_json`` is the single source of truth for hashing and DSSE payload
encoding (unchanged by the in-toto migration).

``pae`` is the DSSE v1 Pre-Authentication Encoding exactly as specified by
the DSSE protocol
(https://github.com/secure-systems-lab/dsse/blob/master/protocol.md):

    PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body

where LEN is the ASCII-encoded decimal byte length and body is the DECODED
payload bytes (never the base64 text). This is byte-for-byte the encoding
cosign and securesystemslib produce.

Migration note (B-08): the pre-migration ``pae`` here used 8-byte
little-endian binary lengths (``struct.pack("<Q", ...)``) while its docstring
claimed cosign compatibility — the claim was false, and a second divergent
copy (``governed_action.dsse_pae``, decimal) existed in the same package.
The pinned ``in-toto-attestation`` 0.9.3 wheel intentionally ships no DSSE
envelope/PAE code (verified by inspection: it contains the Statement /
ResourceDescriptor / predicate protobuf bindings only), so this module holds
the single spec-pinned PAE implementation shared by every signer and
verifier in this package.
"""
from __future__ import annotations

import json


def canonical_json(obj: object) -> bytes:
    """Return compact, sorted-keys JSON encoded as UTF-8 bytes.

    Used as the single source of truth for hashing and DSSE payload encoding.

    Args:
        obj: Any JSON-serialisable Python object.

    Returns:
        UTF-8 bytes with sorted keys and no extra whitespace.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE v1 Pre-Authentication Encoding (spec-exact, cosign-compatible).

    Format (lengths are ASCII decimal, over the DECODED payload bytes):
        DSSEv1 SP <len(type)> SP <type> SP <len(body)> SP <body>

    Args:
        payload_type: DSSE payload type URI string (e.g.
            "application/vnd.in-toto+json").
        body: Raw payload bytes (canonical_json output, before base64).

    Returns:
        PAE-encoded bytes ready for ECDSA-P256-SHA256 signing.

    Raises:
        ValueError: If payload_type is empty or not a string.
        TypeError: If body is not bytes.
    """
    if not isinstance(payload_type, str) or not payload_type:
        raise ValueError("payload_type must be a non-empty string")
    if not isinstance(body, bytes):
        raise TypeError("body must be bytes")
    encoded_type = payload_type.encode("utf-8")
    return b" ".join(
        (
            b"DSSEv1",
            str(len(encoded_type)).encode("ascii"),
            encoded_type,
            str(len(body)).encode("ascii"),
            body,
        )
    )
