# apps/

Source of truth on GitHub for two Hugging Face Spaces that previously had no
GitHub repo and only a static `python -m http.server` container:

| App | Space | Backend |
|:--|:--|:--|
| Receipts Chain Explorer | `SZLHOLDINGS/szl-receipts-chain` | `receipts_chain_explorer/server.py`: `/healthz`, read-only `/api/receipts` over the public `frontier-54-runs` dataset (60 s cache, HTTP 502 on upstream failure, never fabricated) |
| Khipu receipt playground | `SZLHOLDINGS/khipu-playground` | `khipu_playground/server.py`: `/healthz`, `POST /api/sha256` (≤64 KiB, nothing stored) |

Both are stdlib-only Python (no new dependencies) and ship a Dockerfile that
listens on 7860. Run locally: `python apps/receipts_chain_explorer/server.py`.

Frontends (`index.html`) are copied byte-for-byte from the live Spaces at
2026-11-27. Nothing in this directory publishes to Hugging Face; syncing a
Space from here is a separate, explicitly approved step.
