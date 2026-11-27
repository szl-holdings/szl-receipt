# SPDX-License-Identifier: Apache-2.0
"""Receipts Chain Explorer backend (stdlib only).

Serves the explorer frontend and a read-only JSON API over the public
SZLHOLDINGS/frontier-54-runs dataset. Upstream failures are reported as
HTTP 502 with the error; no receipt data is ever fabricated.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP = "receipts-chain-explorer"
HERE = Path(__file__).resolve().parent
DATASET = os.environ.get("SZL_RECEIPTS_DATASET", "SZLHOLDINGS/frontier-54-runs")
TREE_URL = f"https://huggingface.co/api/datasets/{DATASET}/tree/main"
CACHE_TTL_S = 60.0
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/index.html": ("index.html", "text/html; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}

_cache: dict[str, object] = {"at": 0.0, "body": None}
_lock = threading.Lock()


def fetch_tree(opener=urllib.request.urlopen) -> list[dict]:
    """Return the dataset root listing as [{path, type, size, oid}]."""
    req = urllib.request.Request(TREE_URL, headers={"User-Agent": f"szl-{APP}"})
    with opener(req, timeout=10) as resp:
        raw = json.loads(resp.read().decode("utf-8"))
    return [{k: x.get(k) for k in ("path", "type", "size", "oid")} for x in raw]


def receipts_payload(opener=urllib.request.urlopen, now=time.time) -> tuple[int, dict]:
    with _lock:
        if _cache["body"] is not None and now() - float(_cache["at"]) < CACHE_TTL_S:
            return HTTPStatus.OK, _cache["body"]  # type: ignore[return-value]
    try:
        items = fetch_tree(opener)
    except Exception as exc:  # fail closed, report honestly
        return HTTPStatus.BAD_GATEWAY, {"status": "UPSTREAM_ERROR", "source": DATASET,
                                        "error": type(exc).__name__}
    body = {"status": "MEASURED", "source": DATASET, "fetched_at": int(now()),
            "count": len(items), "items": items}
    with _lock:
        _cache.update(at=now(), body=body)
    return HTTPStatus.OK, body


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
            self._json(HTTPStatus.OK, {"status": "ok", "app": APP, "source": DATASET})
        elif path == "/api/receipts":
            code, body = receipts_payload()
            self._json(code, body)
        elif path in STATIC:
            name, ctype = STATIC[path]
            f = HERE / name
            if f.is_file():
                self._send(HTTPStatus.OK, f.read_bytes(), ctype)
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def log_message(self, fmt: str, *args) -> None:  # keep logs terse
        pass


def make_server(host: str = "0.0.0.0", port: int = 7860) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    make_server(port=int(os.environ.get("PORT", "7860"))).serve_forever()
