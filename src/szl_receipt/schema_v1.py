"""Canonical HF model receipt schema v1 (szl.receipt.model/v1) with rail-honesty validation.

Pure-stdlib. A v1 receipt binds a HF model artifact set to its GitHub source-of-truth commit,
its eval evidence, and the TRUE identity of the backend that produced or measured it.
Rail-aliasing is a hard failure: a receipt may not present an aliased community rail as its own backend."""

import re

SCHEMA_ID = "szl.receipt.model/v1"
SHA256_RE = re.compile("^[0-9a-f]{64}$")
COMMIT_RE = re.compile("^[0-9a-f]{40}$")
ISO_RE = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

# Community rails measured 2026-11-23 (obl16 lap, device ollama /api/tags remote metadata):
# all three resolve to ONE shared remote backend gemma4:31b at ollama.com. They are advisory
# rails only and may never be recorded as distinct model identities.
ALIASED_RAILS = {
    spelling: "gemma4:31b"
    for rail in (
        "treyleo16/claude-opus-5-5",
        "treyleo16/gpt-6-1-sol",
        "treyleo16/gpt-6-astra",
    )
    for spelling in (rail, f"{rail}:latest")
}

REQUIRED_TOP = ("schema", "receipt_id", "model_id", "artifacts", "source_of_truth",
                 "eval", "runtime", "provenance", "generated_at", "generator")
REQUIRED_SOT = ("github_repo", "commit")
REQUIRED_RUNTIME = ("backend_true_identity",)
REQUIRED_EVAL = ("dataset", "revision", "metric", "value", "repro_command")
REQUIRED_PROV = ("license",)

class SchemaError(ValueError):
    """Raised when a receipt violates the v1 schema."""

class RailAliasingError(SchemaError):
    """Raised when a receipt presents an aliased community rail as its own backend."""


def validate(doc):
    """Validate a v1 receipt. Returns a list of error strings; empty list means valid."""
    errs = []
    if not isinstance(doc, dict):
        return ["doc: must be a JSON object"]
    for k in REQUIRED_TOP:
        v = doc.get(k)
        if v is None or v == "" or v == [] or v == {}:
            errs.append(k + ": required and non-empty")
    if doc.get("schema") != SCHEMA_ID:
        errs.append("schema: must be exactly " + SCHEMA_ID)
    for i, art in enumerate(doc.get("artifacts") or []):
        if not isinstance(art, dict) or not art.get("path"):
            errs.append("artifacts[" + str(i) + "].path: required")
            continue
        s = str(art.get("sha256") or "")
        if not SHA256_RE.match(s):
            errs.append("artifacts[" + str(i) + "].sha256: must be lowercase hex sha256")
    sot = doc.get("source_of_truth") or {}
    if isinstance(sot, dict):
        for k in REQUIRED_SOT:
            if not sot.get(k):
                errs.append("source_of_truth." + k + ": required")
        c = str(sot.get("commit") or "")
        if c and not COMMIT_RE.match(c):
            errs.append("source_of_truth.commit: must be a full 40-hex git sha (no branch or tag names)")
    for i, ev in enumerate(doc.get("eval") or []):
        if not isinstance(ev, dict):
            errs.append("eval[" + str(i) + "]: must be an object")
            continue
        for k in REQUIRED_EVAL:
            if ev.get(k) in (None, ""):
                errs.append("eval[" + str(i) + "]." + k + ": required")
    runtime = doc.get("runtime") or {}
    if isinstance(runtime, dict):
        for k in REQUIRED_RUNTIME:
            if not runtime.get(k):
                errs.append("runtime." + k + ": required")
        declared = runtime.get("declared_backend")
        true_id = runtime.get("backend_true_identity")
        if declared in ALIASED_RAILS:
            if true_id != ALIASED_RAILS[declared]:
                errs.append("runtime.backend_true_identity: RAIL-ALIASING VIOLATION: " + declared
                            + " resolves to shared backend " + ALIASED_RAILS[declared]
                            + "; the receipt must record that measured backend, not alias the rail")
    prov = doc.get("provenance") or {}
    if isinstance(prov, dict):
        for k in REQUIRED_PROV:
            if not prov.get(k):
                errs.append("provenance." + k + ": required")
    g = str(doc.get("generated_at") or "")
    if g and not ISO_RE.match(g):
        errs.append("generated_at: must be ISO-8601 UTC ending in Z")
    return errs


def validate_or_raise(doc):
    errs = validate(doc)
    if errs:
        raise SchemaError("; ".join(errs))
    aliased = (doc.get("runtime") or {}).get("declared_backend") in ALIASED_RAILS
    if aliased and "RAIL-ALIASING" in " ".join(errs):
        raise RailAliasingError("; ".join(errs))
    return True
