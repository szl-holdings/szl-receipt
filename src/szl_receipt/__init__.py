# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""
szl-receipt — shared signed-receipt library for SZL components.

Provides cryptographically signed per-inference receipts using
DSSE/ECDSA-P256-SHA256 (cosign-compatible), with an UNSIGNED-honest
fallback when no signing key is present.

ORCID: 0009-0001-0110-4173

Public API
----------
::

    from szl_receipt import Receipt, sign_receipt, verify_receipt, generate_keypair, PAYLOAD_TYPE

    # Build a receipt
    r = Receipt(kind="inference", body={"model": "gpt-4o", "policy": "allow"})
    digest = r.digest()          # SHA-256 hex over canonical_json(body)

    # Keyless (UNSIGNED-honest)
    env = sign_receipt(r, private_key_pem=None, organ="a11oy")
    ok, detail = verify_receipt(env)       # -> (False, "unsigned-honest")

    # Signed
    priv_pem, pub_pem = generate_keypair()
    env2 = sign_receipt(r, private_key_pem=priv_pem, organ="a11oy")
    ok, detail = verify_receipt(env2, public_key_pem=pub_pem)  # -> (True, "ok")

cosign verification
-------------------
Save the public key to ``organ.pub``, then::

    cosign verify-blob --key organ.pub \\
        --payload <(echo -n "$payload_b64" | base64 -d) \\
        --signature <(echo -n "$sig_b64" | base64 -d)
"""
from __future__ import annotations

from . import attest
from ._sign import PAYLOAD_TYPE, generate_keypair
from .attest import (
    IN_TOTO_STATEMENT_TYPE,
    build_statement,
    compliance_evidence,
    slsa_predicate,
    verify_statement,
)
from .receipt import Receipt, sign_receipt, verify_receipt

__version__ = "0.2.0"
__author__ = "SZL Contributors"
__license__ = "Apache-2.0"

__all__ = [
    "Receipt",
    "sign_receipt",
    "verify_receipt",
    "generate_keypair",
    "PAYLOAD_TYPE",
    # standards-interop + compliance-evidence attestation (shared home)
    "attest",
    "build_statement",
    "slsa_predicate",
    "compliance_evidence",
    "verify_statement",
    "IN_TOTO_STATEMENT_TYPE",
]
