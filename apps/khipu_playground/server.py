# SPDX-License-Identifier: Apache-2.0
"""Khipu receipt playground backend (stdlib only).

Serves the playground frontend plus a small, local-only hashing API:
POST /api/sha256 with a body of up to 64 KiB returns its SHA-256 hex digest,
so visitors can reproduce a receipt hash themselves. Nothing is stored.
"""
from __future__ import annotations

import hashlib
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP = "khipu-playground"
HERE = Path(__file__).resolve().parent
MAX_BODY = 64 * 1024


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Handler(BaseHTTPRequestHandler):
    server_version = f"szl-{APP}"

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/healthz", "/readyz"):
            self._json(HTTPStatus.OK, {"status": "ok", "app": APP})
        elif path in ("/", "/index.html"):
            self._send(HTTPStatus.OK, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != "/api/sha256":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": f"body must be 0..{MAX_BODY} bytes"})
            return
        data = self.rfile.read(length)
        self._json(HTTPStatus.OK, {"algorithm": "sha256", "bytes": len(data), "digest": sha256_hex(data)})

    def log_message(self, fmt: str, *args) -> None:
        pass


def make_server(host: str = "0.0.0.0", port: int = 7860) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    make_server(port=int(os.environ.get("PORT", "7860"))).serve_forever()
