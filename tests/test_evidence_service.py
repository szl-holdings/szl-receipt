# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""Service routes: read-only, fail-closed, MISSING is first-class data."""
import json
import pathlib
import threading
import urllib.error
import urllib.request

import pytest

from szl_receipt.evidence.service import build_server

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "evidence"


@pytest.fixture(scope="module")
def server_url():
    server = build_server(
        str(FIXTURES), viewer_dir=None, host="127.0.0.1", port=0
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


def _get(url, path, status=200):
    req = urllib.request.Request(url + path, method="GET")
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        code, body, headers = resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as err:  # pragma: no cover - error path
        code, body, headers = err.code, err.read(), err.headers
    assert code == status, body[:400]
    assert headers.get("Content-Type", "").startswith("application/json")
    assert headers.get("Access-Control-Allow-Origin") == "*"
    return json.loads(body.decode("utf-8"))


def test_models_list_has_denominator(server_url):
    data = _get(server_url, "/api/models")
    assert data["denominator"] == 3
    assert len(data["models"]) == 3
    classifications = {m["classification"] for m in data["models"]}
    assert classifications == {
        "fully_evidenced",
        "partially_evidenced",
        "inventory_only",
    }


def test_record_route_includes_gaps_for_missing_slots(server_url):
    data = _get(server_url, "/api/models/szl-canary-partial")
    assert data["classification"] == "partially_evidenced"
    assert data["slots"]["evaluation"]["status"] == "MISSING"
    assert "named_gap" in data["slots"]["evaluation"]
    assert data["slots"]["identity"]["status"] == "MEASURED"


def test_evidence_route_excludes_and_names(server_url):
    data = _get(server_url, "/api/models/szl-canary-partial/evidence")
    statuses = [c["status"] for c in data["verified_claims"]]
    assert statuses and all(
        s in ("MEASURED", "REPRODUCED") for s in statuses
    )
    # the exclusions are named, so absence never looks like completeness
    assert data["excluded_gaps"]
    assert "evaluation" in data["excluded_gaps"]


def test_evidence_route_for_inventory_only_empty_but_named(server_url):
    data = _get(server_url, "/api/models/szl-canary-inventory-only/evidence")
    assert data["verified_claims"] == []
    assert len(data["excluded_gaps"]) == 6


def test_coverage_endpoint_denominator(server_url):
    data = _get(server_url, "/api/coverage")
    assert data["denominator"] == 3
    assert data["classification_counts"]["fully_evidenced"] == 1
    assert isinstance(data["negative_evidence"], list)


def test_coverage_rejects_non_utc_as_of(server_url):
    _get(server_url, "/api/coverage?as_of=2026-11-23T00:00:00", status=400)


def test_compare_endpoint(server_url):
    data = _get(
        server_url,
        "/api/compare?ids=szl-canary-measured,szl-canary-partial",
    )
    assert data["unknown"] == []
    assert len(data["models"]) == 2
    assert data["models"][1]["slots"]["evaluation"] == "MISSING"


def test_compare_requires_ids(server_url):
    _get(server_url, "/api/compare", status=400)


def test_unknown_model_404_is_json(server_url):
    data = _get(server_url, "/api/models/who", status=404)
    assert data["error"]["code"] == "not_found"


def test_unknown_route_404(server_url):
    _get(server_url, "/api/nope", status=404)


def test_no_pass_string_anywhere(server_url):
    for path in (
        "/api/models",
        "/api/models/szl-canary-partial",
        "/api/models/szl-canary-inventory-only/evidence",
        "/api/coverage",
    ):
        payload = json.dumps(_get(server_url, path)).lower()
        assert "pass" not in payload.replace("passivity", "")


def test_fail_closed_on_invalid_evidence_dir(tmp_path):
    (tmp_path / "bad.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(Exception):
        build_server(str(tmp_path), viewer_dir=None, port=0)
