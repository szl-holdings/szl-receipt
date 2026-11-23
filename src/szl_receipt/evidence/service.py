# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""Read-only receipt-evidence HTTP service (stdlib only).

Serves a validated :class:`EvidenceInventory` plus a static viewer:

    GET /api/models                     -> list with classifications
    GET /api/models/{id}                -> full record (slots + claims)
    GET /api/models/{id}/evidence       -> verified claims only
    GET /api/coverage                   -> coverage ledger (+ ?as_of=)
    GET /api/compare?ids=a,b            -> side-by-side claim matrix
    GET /  GET /app.js  GET /style.css  -> static viewer (when present)

Doctrine:
  - Read-only. No endpoint mutates state; no cookies; no auth bypass
    surface because there is no auth at all — this is a public evidence
    browser, and the inventory is loaded once at startup.
  - Fail-closed: the service refuses to start on an invalid evidence
    directory (the inventory loader is the gate).
  - MISSING is data: gaps are first-class responses, rendered as
    MISSING with named gaps — never as zero, "passed", or hidden.
  - CORS ``*``: the JSON is meant to be embedded by GitHub Pages and
    HF Space viewers, which are static hosts without a backend.

Run::

    python -m szl_receipt.evidence.service --evidence-dir receipts/evidence --port 8787
"""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from .inventory import EvidenceInventory, InventoryLoadError, ModelEvidence

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
}

_VIEWER_FILES = ("index.html", "app.js", "style.css")


def _parse_as_of(value: str) -> Optional[str]:
    """Validate the optional ?as_of= coverage staleness instant."""
    from .claims import is_valid_utc_timestamp

    if value and not is_valid_utc_timestamp(value):
        raise ValueError(
            "as_of must be an RFC3339 UTC (Z) timestamp, e.g. "
            "2026-11-23T00:00:00Z"
        )
    return value or None


class EvidenceService:
    """Wires an inventory to HTTP handlers. Pure wiring, no I/O secrets."""

    def __init__(self, inventory: EvidenceInventory, viewer_dir: Optional[Path] = None):
        self.inventory = inventory
        self.viewer_dir = Path(viewer_dir) if viewer_dir else None

    # -- JSON routes ---------------------------------------------------

    def handle(self, path: str, query: str) -> Tuple[int, Dict[str, Any]]:
        parsed = urlparse(path)
        segments = [unquote(s) for s in parsed.path.strip("/").split("/") if s]
        params = parse_qs(query)
        try:
            as_of = _parse_as_of((params.get("as_of") or [""])[0])
        except ValueError as exc:
            return 400, {"error": {"code": "bad_request", "message": str(exc)}}
        if segments == ["api", "models"]:
            return 200, self._models()
        if len(segments) == 3 and segments[:2] == ["api", "models"]:
            record = self.inventory.get(segments[2])
            if record is None:
                return self._not_found(segments[2])
            return 200, self._record(record)
        if len(segments) == 4 and segments[:2] == ["api", "models"]:
            record = self.inventory.get(segments[2])
            if record is None:
                return self._not_found(segments[2])
            if segments[3] == "evidence":
                return 200, self._evidence(record)
            return 404, {
                "error": {
                    "code": "not_found",
                    "message": f"unknown model resource {segments[3]!r}",
                }
            }
        if segments == ["api", "coverage"]:
            return 200, self._coverage(as_of)
        if segments == ["api", "compare"]:
            ids_param = (params.get("ids") or [""])[0]
            ids = [i for i in (s.strip() for s in ids_param.split(",")) if i]
            if not ids:
                return 400, {
                    "error": {
                        "code": "bad_request",
                        "message": "provide ?ids=model-a,model-b",
                    }
                }
            return 200, self.inventory.compare(ids)
        return 404, {
            "error": {
                "code": "not_found",
                "message": f"no route for {path!r}",
            }
        }

    def _models(self) -> Dict[str, Any]:
        models = [
            {
                "model_id": r.model_id,
                "revision": r.revision,
                "classification": r.classification,
            }
            for r in self.inventory.records
        ]
        return {"denominator": len(self.inventory), "models": models}

    def _record(self, record: ModelEvidence) -> Dict[str, Any]:
        return record.to_dict()

    def _evidence(self, record: ModelEvidence) -> Dict[str, Any]:
        verified = [
            c.to_dict()
            for c in record.claims
            if c.verified
        ]
        return {
            "model_id": record.model_id,
            "revision": record.revision,
            "verified_claims": verified,
            # The verified view still names what it excludes — an empty
            # verified list must never look like "everything fine".
            "excluded_gaps": record.slot_gaps(),
        }

    def _coverage(self, as_of: Optional[str]) -> Dict[str, Any]:
        from datetime import datetime

        instant = (
            datetime.fromisoformat(as_of.replace("Z", "+00:00"))
            if as_of
            else None
        )
        return self.inventory.coverage(as_of=instant)

    @staticmethod
    def _not_found(model_id: str) -> Tuple[int, Dict[str, Any]]:
        return 404, {
            "error": {
                "code": "not_found",
                "message": f"model {model_id!r} is not in the inventory; "
                "not-in-inventory is a data point, not a bug",
            }
        }

    # -- static viewer -------------------------------------------------

    def viewer_bytes(self, path: str) -> Optional[Tuple[bytes, str]]:
        name = path.lstrip("/") or "index.html"
        if name == "index.html" or name in _VIEWER_FILES:
            fp = self.viewer_dir / name if self.viewer_dir else None
            if fp and fp.is_file():
                ctype = _CONTENT_TYPES.get(
                    fp.suffix, "application/octet-stream"
                )
                return fp.read_bytes(), ctype
        return None


def make_handler(service: EvidenceService):
    class Handler(BaseHTTPRequestHandler):
        server_version = "szl-evidence/0.1"

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8")

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            parsed = urlparse(self.path)
            static = service.viewer_bytes(parsed.path)
            if static is not None:
                self._send(200, static[0], static[1])
                return
            status, payload = service.handle(parsed.path, parsed.query)
            self._send_json(status, payload)

        def do_HEAD(self) -> None:  # noqa: N802
            self.do_GET()

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write(
                "%s - %s\n" % (self.address_string(), fmt % args)
            )

    return Handler


def build_server(
    evidence_dir: str,
    viewer_dir: Optional[str] = None,
    host: str = "127.0.0.1",
    port: int = 8787,
) -> ThreadingHTTPServer:
    """Load + validate the inventory, then bind. Fails before binding."""
    inventory = EvidenceInventory.load_directory(evidence_dir)
    service = EvidenceService(
        inventory,
        viewer_dir=Path(viewer_dir) if viewer_dir else None,
    )
    server = ThreadingHTTPServer((host, port), make_handler(service))
    return server


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Read-only receipt-evidence HTTP service"
    )
    ap.add_argument("--evidence-dir", required=True)
    ap.add_argument("--viewer-dir", default=None)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args(argv)
    try:
        server = build_server(
            args.evidence_dir, args.viewer_dir, args.host, args.port
        )
    except InventoryLoadError as exc:
        print(f"::error::evidence inventory rejected: {exc}", file=sys.stderr)
        return 2
    print(
        f"szl-evidence serving {args.evidence_dir} on "
        f"http://{args.host}:{args.port}",
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
