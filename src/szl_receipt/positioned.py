# SPDX-License-Identifier: Apache-2.0
"""Opt-in positioned DSSE receipts. No clock, key discovery, or v1 fallback."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ._canonical import pae
from ._sign import _load_private_key, _load_public_key
from .receipt import Receipt

_MAX_POSITION = (1 << 53) - 1
_KIND = re.compile(r"[a-z][a-z0-9-]{0,63}")
_LOG_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")


def _type(kind: str) -> str:
    if not isinstance(kind, str) or not _KIND.fullmatch(kind):
        raise ValueError("kind must be a lowercase receipt-kind label")
    return f"application/vnd.szl.receipt.positioned.v1.{kind}+json"


def _scope(log_id: str, position: int) -> None:
    if not isinstance(log_id, str) or not _LOG_ID.fullmatch(log_id):
        raise ValueError("invalid log_id")
    if type(position) is not int or not 0 <= position <= _MAX_POSITION:
        raise ValueError("position must be a nonnegative safe integer")


def _keyid(public_key: ec.EllipticCurvePublicKey) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


@dataclass(frozen=True)
class KeyWindow:
    """Caller-owned policy for one P-256 key, log, kind and inclusive range."""

    public_key_pem: bytes | str
    log_id: str
    kind: str
    first: int
    last: int

    def __post_init__(self) -> None:
        _type(self.kind)
        _scope(self.log_id, self.first)
        _scope(self.log_id, self.last)
        if self.first > self.last:
            raise ValueError("inverted positional window")
        _load_public_key(self.public_key_pem)


def sign_positioned_receipt(
    receipt: Receipt,
    private_key_pem: bytes | str | None,
    *,
    log_id: str,
    position: int,
) -> dict:
    """Emit one JCS payload; sign its exact bytes or return an unsigned envelope."""
    _scope(log_id, position)
    payload_type = _type(receipt.kind)
    if not isinstance(receipt.body, dict):
        raise TypeError("receipt body must be an object")
    payload = rfc8785.dumps(
        {"body": receipt.body, "log_id": log_id, "position": position}
    )
    signatures = []
    if private_key_pem not in (None, "", b""):
        key = _load_private_key(private_key_pem)
        sig = key.sign(pae(payload_type, payload), ec.ECDSA(hashes.SHA256()))
        signatures.append(
            {
                "keyid": _keyid(key.public_key()),
                "sig": base64.b64encode(sig).decode("ascii"),
            }
        )
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": signatures,
    }


def _json_integer(text: str) -> int | float:
    # ECMAScript writes some binary64 floats (e.g. 1e20) as integer tokens.
    # Preserve those on reserialization; the byte comparison rejects rounding
    # aliases. The position itself must be an exact safe integer.
    if len(text.lstrip("-")) <= 16 and abs(value := int(text)) <= _MAX_POSITION:
        return value
    return float(text)


def _decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise TypeError("expected base64 string")
    raw = base64.b64decode(value, validate=True)
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("expected canonical base64")
    return raw


def verify_positioned_receipt(
    envelope: dict,
    *,
    window: KeyWindow,
    expected_position: int,
) -> tuple[bool, str]:
    """Verify under trusted caller inputs, never under envelope-supplied policy.

    Success proves authenticity within the supplied scope, not log inclusion.
    """
    if not isinstance(window, KeyWindow):
        return False, "invalid-key-window"
    if (
        type(expected_position) is not int
        or not window.first <= expected_position <= window.last
    ):
        return False, "position-outside-key-window"
    if not isinstance(envelope, dict) or set(envelope) != {
        "payloadType",
        "payload",
        "signatures",
    }:
        return False, "invalid-envelope"
    payload_type = _type(window.kind)
    if envelope["payloadType"] != payload_type:
        return False, "payload-type-mismatch"
    signatures = envelope["signatures"]
    if not isinstance(signatures, list):
        return False, "invalid-signatures"
    if not signatures:
        return False, "unsigned-honest"
    if (
        len(signatures) != 1
        or not isinstance(signatures[0], dict)
        or set(signatures[0]) != {"keyid", "sig"}
    ):
        return False, "invalid-signatures"
    try:
        key = _load_public_key(window.public_key_pem)
        if signatures[0]["keyid"] != _keyid(key):
            return False, "key-id-mismatch"
        raw = _decode(envelope["payload"])
        key.verify(
            _decode(signatures[0]["sig"]),
            pae(payload_type, raw),
            ec.ECDSA(hashes.SHA256()),
        )
        record = json.loads(raw.decode("utf-8"), parse_int=_json_integer)
        # Byte equality also rejects duplicate members (even identical ones),
        # noncanonical number spellings, alternate key order, escapes and whitespace.
        if rfc8785.dumps(record) != raw:
            return False, "noncanonical-payload"
    except InvalidSignature:
        return False, "signature-mismatch"
    except (ValueError, TypeError, RecursionError):
        return False, "invalid-payload-or-encoding"
    if (
        not isinstance(record, dict)
        or set(record) != {"body", "log_id", "position"}
        or not isinstance(record["body"], dict)
    ):
        return False, "invalid-record"
    if (
        record["log_id"] != window.log_id
        or type(record["position"]) is not int
        or record["position"] != expected_position
    ):
        return False, "position-or-log-mismatch"
    return True, "ok"
