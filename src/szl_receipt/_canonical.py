# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""
Canonical JSON serialisation and DSSE Pre-Authentication Encoding.

Primitives copied verbatim from khipu-consensus/python/khipu_consensus/__init__.py
to ensure byte-for-byte compatibility with cosign verify-blob.
"""
from __future__ import annotations

import json
import struct


def canonical_json(obj: object) -> bytes:
    """Return compact, sorted-keys JSON encoded as UTF-8 bytes.

    Equivalent to khipu-consensus canonical_json — used as the single
    source of truth for hashing and DSSE payload encoding.

    Args:
        obj: Any JSON-serialisable Python object.

    Returns:
        UTF-8 bytes with sorted keys and no extra whitespace.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (DSSEv1).

    Encodes the payload type and body according to the DSSE specification
    so that the signed bytes are identical to those produced by cosign.

    Format (little-endian 64-bit lengths):
        DSSEv1 SP <len(type)> SP <type> SP <len(body)> SP <body>

    Args:
        payload_type: DSSE payload type URI string (e.g.
            "application/vnd.szl.receipt+json").
        body: Raw payload bytes (canonical_json output).

    Returns:
        PAE-encoded bytes ready for ECDSA-P256-SHA256 signing.
    """
    def _enc(s: bytes) -> bytes:
        return struct.pack("<Q", len(s)) + s

    pt = payload_type.encode("utf-8")
    return b"DSSEv1 " + _enc(pt) + b" " + _enc(body)
