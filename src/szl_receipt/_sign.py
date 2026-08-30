# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""
DSSE/ECDSA-P256-SHA256 sign and verify primitives on the pinned maintained
stack — no hand-rolled crypto anywhere.

Signing algorithm (DSSE v1, cosign-compatible):
  1. canonical_json(body) -> payload bytes
  2. pae(PAYLOAD_TYPE, payload) -> signing bytes  (spec-exact: ASCII decimal
     lengths over the DECODED payload bytes — see ._canonical)
  3. ECDSA P-256 over SHA-256 of the PAE -> DER signature -> base64

All key and signature arithmetic is the pinned ``cryptography`` 50.0.1
library; keys are constrained to ECDSA P-256 (the browser-verifiable curve
locked by the v11 doctrine). in-toto Statement construction lives in
``_intoto`` (pinned ``in-toto-attestation`` 0.9.3).

Migration note (B-08): the pre-migration PAE used non-standard 8-byte
little-endian lengths, so receipts signed before the migration are NOT
verifiable here (they were never cosign-verifiable either). Payload bytes,
digests, and the envelope shape are unchanged; only the signature coverage
moved to the standard PAE. See MIGRATION.md.

cosign verify-blob compatibility (now true in fact):
  cosign verify-blob --key <organ>.pub \\
      --payload <(echo -n '<b64_payload>' | base64 -d) \\
      --signature <(echo -n '<sig_b64>' | base64 -d)
"""
from __future__ import annotations

import base64
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

from ._canonical import canonical_json, pae

#: DSSE payload type for SZL receipts (also exported from top-level).
PAYLOAD_TYPE: str = "application/vnd.szl.receipt+json"


def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate an ECDSA-P256 keypair as PEM bytes.

    Returns:
        Tuple of (private_key_pem, public_key_pem) as bytes.
        Both are unencrypted PEM-encoded PKCS8/SubjectPublicKeyInfo.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _load_private_key(private_key_pem: bytes | str) -> ec.EllipticCurvePrivateKey:
    raw = (
        private_key_pem.encode("utf-8")
        if isinstance(private_key_pem, str)
        else private_key_pem
    )
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("szl-receipt requires an ECDSA P-256 private key")
    return key


def _load_public_key(public_key_pem: bytes | str) -> ec.EllipticCurvePublicKey:
    raw = (
        public_key_pem.encode("utf-8")
        if isinstance(public_key_pem, str)
        else public_key_pem
    )
    key = serialization.load_pem_public_key(raw)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("szl-receipt requires an ECDSA P-256 public key")
    return key


def _signing_bytes(body_dict: object) -> Tuple[bytes, bytes]:
    """Return (payload_bytes, pae_bytes) for a body dict."""
    payload = canonical_json(body_dict)
    signing = pae(PAYLOAD_TYPE, payload)
    return payload, signing


def sign_dsse(body_dict: object, private_key_pem: bytes | str) -> Tuple[str, str]:
    """Sign *body_dict* with ECDSA-P256-SHA256 over the standard DSSE PAE.

    Args:
        body_dict: Receipt body — must be JSON-serialisable.
        private_key_pem: PEM-encoded ECDSA-P256 private key.

    Returns:
        Tuple of (payload_b64, signature_b64) where both are
        standard base64-encoded strings (not URL-safe, matching cosign).

    Raises:
        ValueError: If the key is not an ECDSA P-256 private key.
    """
    private_key = _load_private_key(private_key_pem)
    payload, signing = _signing_bytes(body_dict)

    der_sig = private_key.sign(signing, ec.ECDSA(hashes.SHA256()))
    payload_b64 = base64.b64encode(payload).decode("ascii")
    sig_b64 = base64.b64encode(der_sig).decode("ascii")
    return payload_b64, sig_b64


def verify_dsse(
    body_dict: object,
    signature_b64: str,
    public_key_pem: bytes | str,
) -> Tuple[bool, str]:
    """Verify a DSSE/ECDSA-P256-SHA256 signature against *body_dict*.

    Args:
        body_dict: The decoded receipt body (must reproduce the same
            canonical_json bytes that were signed).
        signature_b64: Base64-encoded DER signature.
        public_key_pem: PEM-encoded ECDSA-P256 public key.

    Returns:
        (True, "ok") on successful verification.
        (False, "signature mismatch") on any cryptographic failure.
        (False, "invalid key or encoding: ...") on key/encoding errors.
    """
    try:
        public_key = _load_public_key(public_key_pem)
        _, signing = _signing_bytes(body_dict)
        der_sig = base64.b64decode(signature_b64)
        public_key.verify(der_sig, signing, ec.ECDSA(hashes.SHA256()))
        return True, "ok"
    except InvalidSignature:
        return False, "signature mismatch"
    except Exception as exc:  # noqa: BLE001
        return False, f"invalid key or encoding: {exc}"


def body_digest(body_dict: object) -> str:
    """SHA-256 over canonical_json(body_dict), returned as hex string."""
    payload = canonical_json(body_dict)
    return hashlib.sha256(payload).hexdigest()
