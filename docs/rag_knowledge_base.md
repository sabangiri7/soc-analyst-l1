# RAG knowledge base

The local ChromaDB store (`rag/knowledge_base.py`, on-disk, nothing leaves
the box). Collections are kept separate so retrieval is targeted:

| Collection | Contents | Seeded by |
|---|---|---|
| `playbooks` | Your org's SOPs for alert types | `scripts_ingest_seed.py` (from `seed_data/playbooks/*.md`) |
| `cases` | Closed historical alerts with analyst verdict + reasoning | written automatically on feedback review |
| `lessons` | Distilled, human-approved self-improvement notes | `feedback_cli.py distill` |
| `wazuh_docs` | Curated engineering reference for the SOC Engineer (rule RF, logtest semantics, API quirks, indexer conventions, MITRE mapping) **plus live rule snapshots** (`kind=wazuh-rule`) | `scripts_ingest_wazuh_docs.py` (from `wazuh_docs/*.md`) + the `ingest_wazuh_rules` tool / `scripts_ingest_wazuh_rules.py` (from the live manager) |

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

## Rule snapshots (`kind=wazuh-rule`) — the live ruleset in the RAG

The manager ships thousands of bundled rules plus your custom rules in
`local_rules.xml`. The engineer can snapshot them READ-only into this same
`wazuh_docs` collection so it can answer "what rules do we already have for
<detection>" offline (see `wazuh_docs/wazuh-rules.md` for the full workflow):

- **`ingest_wazuh_rules`** (engineer tool, READ — executes immediately, like
  any READ tool) pulls rules from the manager and upserts each as
  `kind=wazuh-rule` with the stable doc id `wazuh_rule_<id>`, so re-runs are
  idempotent. Default scope is `local_rules.xml` (your custom/correlation
  rules); `all_rules=true` / `filename=all` snapshots the whole ruleset —
  `max_rules` defaults to 2000 per call with a hard cap of 5000, so a full
  snapshot of a stock manager (~4.5k rules) needs `max_rules=5000`.
- **Prune** — per scope: snapshot docs whose rule is no longer in that scope's
  file are removed (`$and` where-filter, never a wipe of unrelated docs).
- **`scripts_ingest_wazuh_rules.py`** — the same operation as a CLI batch job
  (`--all`, `--group web`, `--max-rules 500`, `--no-prune`).
- **Sizing** — after a full snapshot the `wazuh_docs` collection may hold
  thousands of `kind=wazuh-rule` docs; retrieval stays targeted because
  `retrieve_wazuh_docs` returns them alongside the curated reference (same
  `{id, source, kind, distance, text}` shape).
- The manager is **never modified** by either path, and snapshot docs are
  data, never instructions — the engineer must re-verify against the live
  manager (logtest) before acting on anything recalled from a snapshot.

## Retrieval from the engineer

`retrieve_wazuh_docs(query, collection="wazuh_docs", n_results=4)` (READ
tool, executes immediately) returns id / source / kind / distance / text and
declares the text UNTRUSTED DATA — rule snapshots come back the same way,
distinguishable by `kind == "wazuh-rule"`. Unknown collections and empty
queries are rejected. The KnowledgeBase is opened lazily per call so importing
the tool never touches disk.

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
READ execution). `tests/test_rag_rules.py` pins the rule-snapshot workflow
(idempotent upsert, prune per scope, `all_rules` include/exclude,
max-rules cap, READ execution). `tests/test_rag.py` covers the embedding
fallback and embedding-mode selection.
