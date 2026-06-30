# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""
Receipt, sign_receipt, and verify_receipt — the public-facing API.

Doctrine (non-negotiable):
  - UNSIGNED-honest: when no private key is provided, signed=False,
    signature="" and note="UNSIGNED-honest: no cosign key present".
  - verify_receipt of a keyless envelope ALWAYS returns
    (False, "unsigned-honest") — it NEVER reports a fake pass.
  - One canonical hash: SHA-256 over canonical_json(body), exposed in
    the envelope as algo="ECDSA-P256-SHA256" (or "UNSIGNED" when keyless).
"""
from __future__ import annotations

import base64
import dataclasses
from typing import Any, Dict, Optional, Tuple

from ._canonical import canonical_json
from ._sign import PAYLOAD_TYPE, body_digest, sign_dsse, verify_dsse

_UNSIGNED_NOTE = "UNSIGNED-honest: no cosign key present"
_ALGO_SIGNED = "ECDSA-P256-SHA256"
_ALGO_UNSIGNED = "UNSIGNED"


@dataclasses.dataclass
class Receipt:
    """Immutable record of a single inference/decision event.

    Args:
        kind: Short label describing the event class (e.g. "inference",
            "policy-decision", "audit").
        body: Arbitrary JSON-serialisable dict carrying the event data.
            Keys are sorted during hashing for determinism.
    """

    kind: str
    body: Dict[str, Any]

    def digest(self) -> str:
        """SHA-256 hex digest over canonical_json(body).

        Stable across Python versions and processes for equal *body* dicts.

        Returns:
            64-character lowercase hex string.
        """
        return body_digest(self.body)


def sign_receipt(
    receipt: Receipt,
    private_key_pem: Optional[str | bytes],
    organ: str = "unknown",
    keyid: str = "",
) -> Dict[str, Any]:
    """Wrap a Receipt in a DSSE envelope, optionally signing it.

    When *private_key_pem* is ``None`` or empty, an UNSIGNED-honest
    envelope is produced — ``signed=False``, ``signature=""``, and
    ``note="UNSIGNED-honest: no cosign key present"``.

    The envelope payload is ``base64(canonical_json(receipt.body))``; the
    signature (when present) covers ``pae(PAYLOAD_TYPE, payload_bytes)``
    with ECDSA-P256-SHA256, identical to khipu-consensus and verifiable
    with ``cosign verify-blob``.

    Args:
        receipt: The Receipt to wrap.
        private_key_pem: PEM-encoded ECDSA-P256 private key, or None/""
            for keyless (UNSIGNED-honest) mode.
        organ: Logical signing authority label (e.g. "a11oy").
        keyid: Optional key identifier string.

    Returns:
        Envelope dict with keys:
            payloadType, payload, signature, signed, organ, keyid,
            digest, algo, note (present only when unsigned).
    """
    digest = receipt.digest()
    payload_bytes = canonical_json(receipt.body)
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")

    keyless = not private_key_pem

    if keyless:
        return {
            "payloadType": PAYLOAD_TYPE,
            "payload": payload_b64,
            "signature": "",
            "signed": False,
            "organ": organ,
            "keyid": keyid,
            "digest": digest,
            "algo": _ALGO_UNSIGNED,
            "note": _UNSIGNED_NOTE,
        }

    # Real DSSE/ECDSA-P256-SHA256 signature
    _, sig_b64 = sign_dsse(receipt.body, private_key_pem)
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": payload_b64,
        "signature": sig_b64,
        "signed": True,
        "organ": organ,
        "keyid": keyid,
        "digest": digest,
        "algo": _ALGO_SIGNED,
    }


def verify_receipt(
    envelope: Dict[str, Any],
    public_key_pem: Optional[str | bytes] = None,
) -> Tuple[bool, str]:
    """Verify the integrity and authenticity of a signed envelope.

    Doctrine:
      - Keyless (``signed==False``) envelopes always return
        ``(False, "unsigned-honest")`` regardless of *public_key_pem*.
        This enforces the UNSIGNED-honest contract — no fake passes.
      - Signed envelopes are verified via DSSE/ECDSA-P256-SHA256.
        The payload is decoded from base64 and checked against the
        PAE of the declared payloadType.

    Args:
        envelope: Dict as returned by ``sign_receipt``.
        public_key_pem: PEM-encoded ECDSA-P256 public key (required for
            signed envelopes; ignored for unsigned).

    Returns:
        ``(True, "ok")`` — valid signature.
        ``(False, "unsigned-honest")`` — envelope was never signed.
        ``(False, "signature mismatch")`` — signature is invalid.
        ``(False, "<error description>")`` — any other failure.
    """
    # UNSIGNED-honest contract — never report a pass for unsigned
    if not envelope.get("signed", False):
        return False, "unsigned-honest"

    if not public_key_pem:
        return False, "no public key provided"

    try:
        payload_bytes = base64.b64decode(envelope["payload"])
    except Exception as exc:  # noqa: BLE001
        return False, f"envelope decode error: {exc}"

    try:
        import json
        body_dict = json.loads(payload_bytes.decode("utf-8"))
    except Exception:  # noqa: BLE001
        # Corrupted payload cannot decode -> treat as tamper / signature mismatch
        return False, "signature mismatch"

    try:
        sig_b64 = envelope["signature"]
        return verify_dsse(body_dict, sig_b64, public_key_pem)
    except Exception as exc:  # noqa: BLE001
        return False, f"envelope decode error: {exc}"
