# SPDX-License-Identifier: Apache-2.0
import io
import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

from apps.khipu_playground import server as kp
from apps.receipts_chain_explorer import server as rce


@contextmanager
def running(mod):
    srv = mod.make_server("127.0.0.1", 0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, r.read()


def test_explorer_health_and_index():
    with running(rce) as base:
        code, body = _get(base + "/healthz")
        assert code == 200 and json.loads(body)["status"] == "ok"
        code, body = _get(base + "/")
        assert code == 200 and b"<html" in body.lower()
        try:
            _get(base + "/../server.py")
            raise AssertionError("expected 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_explorer_receipts_measured_and_fail_closed():
    rce._cache.update(at=0.0, body=None)
    payload = json.dumps([{"path": "r1.json", "type": "file", "size": 3, "oid": "abc", "x": 1}]).encode()
    code, body = rce.receipts_payload(opener=lambda req, timeout: _Resp(payload), now=lambda: 1000.0)
    assert code == 200 and body["status"] == "MEASURED"
    assert body["items"] == [{"path": "r1.json", "type": "file", "size": 3, "oid": "abc"}]

    rce._cache.update(at=0.0, body=None)

    def boom(req, timeout):
        raise urllib.error.URLError("down")

    code, body = rce.receipts_payload(opener=boom, now=lambda: 2000.0)
    assert code == 502 and body["status"] == "UPSTREAM_ERROR" and "items" not in body


def test_playground_sha256_and_limits():
    with running(kp) as base:
        code, body = _get(base + "/healthz")
        assert code == 200
        req = urllib.request.Request(base + "/api/sha256", data=b"khipu", method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            out = json.loads(r.read())
        assert out["digest"] == kp.sha256_hex(b"khipu") and out["bytes"] == 5
        big = urllib.request.Request(base + "/api/sha256", data=b"x" * (kp.MAX_BODY + 1), method="POST")
        try:
            urllib.request.urlopen(big, timeout=5)
            raise AssertionError("expected 413")
        except urllib.error.HTTPError as e:
            assert e.code == 413
