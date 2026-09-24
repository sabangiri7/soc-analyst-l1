# RAG knowledge base

The local ChromaDB store (`rag/knowledge_base.py`, on-disk, nothing leaves
the box). Collections are kept separate so retrieval is targeted:

| Collection | Contents | Seeded by |
|---|---|---|
| `playbooks` | Your org's SOPs for alert types | `scripts_ingest_seed.py` (from `seed_data/playbooks/*.md`) |
| `cases` | Closed historical alerts with analyst verdict + reasoning | written automatically on feedback review |
| `lessons` | Distilled, human-approved self-improvement notes | `feedback_cli.py distill` |
| `wazuh_docs` | Curated engineering reference for the SOC Engineer (rule RF, logtest semantics, API quirks, indexer conventions, MITRE mapping) | `scripts_ingest_wazuh_docs.py` (from `wazuh_docs/*.md`) |

## wazuh_docs (the engineer's reference)

Five live-verified reference docs:

- `wazuh-rules.md` — local rule authoring: id >= 100000, required
  id/level/description, **frequency/timeframe/divide are ATTRIBUTES**,
  frequency rules require `<if_matched_sid>`, frequency/timeframe semantics,
  deployment flow (upload → restart → verify).
- `wazuh-logtest.md` — logtest sessions/tokens, response shape, frequency
  verification (fires on the Nth occurrence; 1/N ratio is expected), plain
  rule expectations, no_decode handling.
- `wazuh-api.md` — connectivity/auth (55000, Basic + run_as), read endpoints
  and the `data.affected_items` envelope, octet-stream PUT, the
  `/manager/status` core-daemon readiness gate, search-vs-`query_string`.
- `wazuh-indexer.md` — indices (`wazuh-alerts-*` vs `wazuh-archives-*`),
  structured bool clauses only, size-0 count verification, fields that
  exist, field_caps schema discovery.
- `mitre-attack-mapping.md` — ATT&CK IDs for web / SSH / network detections,
  joined via `rule.groups` and `rule.mitre.id`.

Keep these docs **short, factual, and verified** — this is what the engineer
retrieves to ground rule and detection work. Re-run the ingest script after
editing them; it upserts by filename stem, so edits refresh in place and
re-runs never duplicate.

## Retrieval from the engineer

`retrieve_wazuh_docs(query, collection="wazuh_docs", n_results=4)` (READ
tool, executes immediately) returns id / source / kind / distance / text and
declares the text UNTRUSTED DATA. Unknown collections and empty queries are
rejected. The KnowledgeBase is opened lazily per call so importing the tool
never touches disk.

## Embedding modes

- default `auto`: chromadb's sentence-transformer download on first use
  (one-time, needs internet) — best retrieval quality, then fully offline.
- `KB_EMBEDDING_MODE=hashing` (or `MOCK_MODE=true`, which implies it):
  deterministic, dependency-free bag-of-words embedding
  (`rag/embeddings.py`) — no network, no model file, noticeable quality
  drop (literal word overlap only). Use for air-gapped/CI/test.
- A collection's embedding function is fixed at creation time in its
  on-disk data; `KnowledgeBase` falls back to whatever is persisted rather
  than crashing if the mode is flipped on existing data.

## Tests

`tests/test_rag_docs.py` covers the `wazuh_docs` collection (ingest
idempotency on a tmp chroma path, tool result shape + rejections, registry
READ execution). `tests/test_rag.py` covers the embedding fallback and
embedding-mode selection.